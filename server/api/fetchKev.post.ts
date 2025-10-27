import { createError, readBody } from 'h3'
import { ofetch } from 'ofetch'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import type { ImportTaskKey, KevEntry } from '~/types'
import { eq, inArray, sql } from 'drizzle-orm'
import { getCachedData } from '../utils/cache'
import { fetchCvssMetrics } from '../utils/cvss'
import { importEnisaCatalog } from '../utils/enisa'
import { importHistoricCatalog } from '../utils/historic'
import {
  completeImportProgress,
  failImportProgress,
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  markTaskSkipped,
  publishTaskEvent,
  setImportPhase,
  startImportProgress,
  updateImportProgress
} from '../utils/import-progress'
import { rebuildCatalog } from '../utils/catalog'
import { getDatabase, getMetadata } from '../utils/sqlite'
import { tables } from '../database/client'
import { rebuildProductCatalog } from '../utils/product-catalog'
import { importMetasploitCatalog } from '../utils/metasploit'
import { importGithubPocCatalog } from '../utils/github-poc'
import { importMarketIntel } from '../utils/market'
import { requireAdminKey } from '../utils/adminAuth'
import type { ImportStrategy } from '../utils/import-types'
import {
  CVELIST_ENRICHMENT_CONCURRENCY,
  clearCvelistMemoryCache,
  enrichBaseEntryWithCvelist,
  syncCvelistRepo,
  flushCvelistCache,
  type EnrichBaseEntryResult,
  type VulnerabilityImpactRecord
} from '../utils/cvelist'
import { mapWithConcurrency } from '../utils/concurrency'

const kevSchema = z.object({
  title: z.string(),
  catalogVersion: z.string(),
  dateReleased: z.string(),
  count: z.number(),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vendorProject: z.string().optional(),
      product: z.string().optional(),
      vulnerabilityName: z.string().optional(),
      dateAdded: z.string().optional(),
      shortDescription: z.string().optional(),
      requiredAction: z.string().optional(),
      dueDate: z.string().nullable().optional(),
      knownRansomwareCampaignUse: z.string().optional(),
      notes: z.string().optional(),
      cwes: z.array(z.string()).optional()
    })
  )
})

const toNotes = (raw: unknown): string[] => {
  if (typeof raw !== 'string') {
    return []
  }

  return raw
    .split(';')
    .map(entry => entry.trim())
    .filter(Boolean)
}

const toJson = (value: unknown): string => JSON.stringify(value ?? [])

const normaliseStoredSeverity = (value: unknown): KevEntry['cvssSeverity'] | null => {
  if (typeof value !== 'string') {
    return null
  }

  switch (value) {
    case 'None':
    case 'Low':
    case 'Medium':
    case 'High':
    case 'Critical':
      return value
    default:
      return null
  }
}

const SOURCE_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

type CvssMetric = {
  score: number | null
  vector: string | null
  version: string | null
  severity: KevEntry['cvssSeverity'] | null
}

const ONE_DAY_MS = 86_400_000

type ImportMode = 'auto' | 'force' | 'cache'
type ImportRequestBody = { mode?: ImportMode; source?: string; strategy?: string }

const IMPORT_SOURCE_ORDER: ImportTaskKey[] = ['kev', 'historic', 'enisa', 'metasploit', 'poc', 'market']

const isImportSourceKey = (value: string): value is ImportTaskKey => {
  return IMPORT_SOURCE_ORDER.includes(value as ImportTaskKey)
}

export default defineEventHandler(async event => {
  requireAdminKey(event)

  if (process.env.NODE_ENV !== 'development') {
    throw createError({
      statusCode: 403,
      statusMessage: 'Catalog import is restricted to development mode'
    })
  }

  const body = await readBody<ImportRequestBody>(event).catch(
    () => ({}) as ImportRequestBody
  )

  const mode = body?.mode ?? 'auto'
  const forceRefresh = mode === 'force'
  const allowStale = mode === 'cache'
  const rawSource = typeof body?.source === 'string' ? body.source.toLowerCase() : 'all'
  const rawStrategy = typeof body?.strategy === 'string' ? body.strategy.toLowerCase() : 'full'
  const strategy: ImportStrategy = rawStrategy === 'incremental' ? 'incremental' : 'full'

  if (allowStale) {
    clearCvelistMemoryCache()
  }

  const sourcesToImport: ImportTaskKey[] =
    rawSource === 'all'
      ? IMPORT_SOURCE_ORDER
      : isImportSourceKey(rawSource)
        ? [rawSource]
        : IMPORT_SOURCE_ORDER

  startImportProgress('Starting vulnerability catalog import', sourcesToImport)

  const shouldImport = (key: ImportTaskKey) => sourcesToImport.includes(key)

  const fallbackCatalogVersion = getMetadata('catalogVersion') ?? ''
  const fallbackDateReleased = getMetadata('dateReleased') ?? ''
  const fallbackEnisaUpdated = getMetadata('enisa.lastUpdatedAt')
  const fallbackMetasploitCommit = getMetadata('metasploit.lastCommit')
  const fallbackMetasploitModules =
    Number.parseInt(getMetadata('metasploit.moduleCount') ?? '0', 10) || 0

  const importStartedAt = new Date().toISOString()

  let catalogVersion = fallbackCatalogVersion
  let dateReleased = fallbackDateReleased
  let enisaLastUpdated = fallbackEnisaUpdated
  let metasploitCommit = fallbackMetasploitCommit
  let metasploitModules = fallbackMetasploitModules
  let importTimestamp = importStartedAt

  let kevImported = 0
  let kevNewCount = 0
  let kevUpdatedCount = 0
  let kevSkippedCount = 0
  let kevRemovedCount = 0
  let kevImportStrategy: ImportStrategy = 'full'
  let historicImported = 0
  let historicNewCount = 0
  let historicUpdatedCount = 0
  let historicSkippedCount = 0
  let historicRemovedCount = 0
  let historicImportStrategy: ImportStrategy = 'full'
  let enisaImported = 0
  let enisaNewCount = 0
  let enisaUpdatedCount = 0
  let enisaSkippedCount = 0
  let enisaRemovedCount = 0
  let enisaImportStrategy: ImportStrategy = 'full'
  let metasploitImported = 0
  let metasploitNewCount = 0
  let metasploitUpdatedCount = 0
  let metasploitSkippedCount = 0
  let metasploitRemovedCount = 0
  let metasploitImportStrategy: ImportStrategy = 'full'
  let pocImported = 0
  let pocNewCount = 0
  let pocUpdatedCount = 0
  let pocSkippedCount = 0
  let pocRemovedCount = 0
  let pocImportStrategy: ImportStrategy = 'full'
  let marketImported = 0
  let marketOfferCount = 0
  let marketProgramCount = 0
  let marketProductCount = 0
  let marketLastCaptureAt: string | null = null
  let marketLastSnapshotAt: string | null = null

  const db = getDatabase()

  try {
    if (!shouldImport('kev')) {
      markTaskSkipped('kev', 'Skipped this run')
    } else {
      markTaskRunning('kev', 'Checking KEV cache')

      try {
        const syncResult = await syncCvelistRepo({ useCachedRepository: allowStale })
        const message = syncResult.updated
          ? 'Synced CVEList repository'
          : 'Using cached CVEList repository'
        markTaskProgress('kev', 0, 0, message)
      } catch (error) {
        const reason = (error as Error).message || 'Unknown error'
        markTaskError('kev', `Failed to sync CVEList repository: ${reason}`)
      }

      try {
        setImportPhase('preparing', { message: 'Checking KEV cache', completed: 0, total: 0 })
        const kevDataset = await getCachedData(
          'kev-feed',
          async () => {
            setImportPhase('preparing', {
              message: 'Downloading latest KEV catalog',
              completed: 0,
              total: 0
            })
            markTaskProgress('kev', 0, 0, 'Downloading latest KEV catalog')
            return ofetch(SOURCE_URL)
          },
          { ttlMs: ONE_DAY_MS, forceRefresh, allowStale }
        )

        markTaskProgress(
          'kev',
          0,
          0,
          kevDataset.cacheHit
            ? 'Using cached KEV catalog'
            : 'Downloaded latest KEV catalog'
        )

        const parsed = kevSchema.safeParse(kevDataset.data)

        if (!parsed.success) {
          throw createError({
            statusCode: 502,
            statusMessage: 'Unable to parse KEV feed',
            data: parsed.error.flatten()
          })
        }

        const baseEntries = parsed.data.vulnerabilities.map((item): KevBaseEntry => {
          const cveId = item.cveID
          const normalised = normaliseVendorProduct(
            {
              vendor: item.vendorProject,
              product: item.product
            },
            undefined,
            undefined,
            {
              vulnerabilityName: item.vulnerabilityName,
              description: item.shortDescription,
              cveId
            }
          )
          return {
            id: `kev:${cveId}`,
            sources: ['kev'],
            cveId,
            vendor: normalised.vendor.label,
            vendorKey: normalised.vendor.key,
            product: normalised.product.label,
            productKey: normalised.product.key,
            affectedProducts: [],
            problemTypes: [],
            vulnerabilityName: item.vulnerabilityName ?? 'Unknown vulnerability',
            description: item.shortDescription ?? '',
            requiredAction: item.requiredAction ?? null,
            dateAdded: item.dateAdded ?? '',
            dueDate: item.dueDate ?? null,
            ransomwareUse: item.knownRansomwareCampaignUse ?? null,
            notes: toNotes(item.notes),
            cwes: Array.isArray(item.cwes) ? item.cwes : [],
            cvssScore: null,
            cvssVector: null,
            cvssVersion: null,
            cvssSeverity: null,
            epssScore: null,
            assigner: null,
            datePublished: item.dateAdded ?? null,
            dateUpdated: null,
            exploitedSince: item.dateAdded ?? null,
            sourceUrl: null,
            pocUrl: null,
            pocPublishedAt: null,
            references: [],
            aliases: cveId ? [cveId] : [],
            metasploitModulePath: null,
            metasploitModulePublishedAt: null,
            internetExposed: false
          }
        })

      type ExistingCvssRow = {
        cve_id: string
        cvss_score: number | null
        cvss_vector: string | null
        cvss_version: string | null
        cvss_severity: string | null
      }

      const baseCveIds = baseEntries.map(entry => entry.cveId)
      const existingCvss = new Map<string, CvssMetric>()

      if (baseCveIds.length > 0) {
        const baseCveIdSet = new Set(baseCveIds)
        const existingRows = db
          .select({
            cve_id: tables.vulnerabilityEntries.cveId,
            cvss_score: tables.vulnerabilityEntries.cvssScore,
            cvss_vector: tables.vulnerabilityEntries.cvssVector,
            cvss_version: tables.vulnerabilityEntries.cvssVersion,
            cvss_severity: tables.vulnerabilityEntries.cvssSeverity
          })
          .from(tables.vulnerabilityEntries)
          .where(eq(tables.vulnerabilityEntries.source, 'kev'))
          .all() as ExistingCvssRow[]

        for (const row of existingRows) {
          if (!baseCveIdSet.has(row.cve_id)) {
            continue
          }

          existingCvss.set(row.cve_id, {
            score: typeof row.cvss_score === 'number' ? row.cvss_score : null,
            vector: typeof row.cvss_vector === 'string' ? row.cvss_vector : null,
            version: typeof row.cvss_version === 'string' ? row.cvss_version : null,
            severity: normaliseStoredSeverity(row.cvss_severity)
          })
        }
      }

      const cvesNeedingFetch = baseEntries
        .filter(entry => {
          const existing = existingCvss.get(entry.cveId)
          return !existing || existing.score === null
        })
        .map(entry => entry.cveId)

      let fetchedCvss: Map<string, CvssMetric> | null = null

      if (cvesNeedingFetch.length > 0) {
        fetchedCvss = await fetchCvssMetrics(cvesNeedingFetch, {
          onStart(total) {
            const message =
              total > 0
                ? `Fetching CVSS metrics (0 of ${total})`
                : 'No CVSS metrics to fetch'
            setImportPhase('fetchingCvss', {
              total,
              completed: 0,
              message
            })
            markTaskProgress('kev', 0, total, message)
          },
          onProgress(completed, total) {
            const message =
              total > 0
                ? `Fetching CVSS metrics (${completed} of ${total})`
                : 'Fetching CVSS metrics'
            updateImportProgress('fetchingCvss', completed, total, message)
            markTaskProgress('kev', completed, total, message)
          }
        })
      } else {
        const reusedCount = baseEntries.length
        const message =
          reusedCount > 0
            ? `Reusing cached CVSS metrics for ${reusedCount} CVE${reusedCount === 1 ? '' : 's'}`
            : 'No CVSS metrics required for this import'
        setImportPhase('fetchingCvss', {
          total: 0,
          completed: 0,
          message
        })
        markTaskProgress('kev', 0, 0, message)
      }

      const cvssMetrics = new Map<string, CvssMetric>()

      for (const base of baseEntries) {
        const existing = existingCvss.get(base.cveId)
        const fetched = fetchedCvss?.get(base.cveId)

        cvssMetrics.set(base.cveId, {
          score: fetched?.score ?? existing?.score ?? null,
          vector: fetched?.vector ?? existing?.vector ?? null,
          version: fetched?.version ?? existing?.version ?? null,
          severity: fetched?.severity ?? existing?.severity ?? null
        })
      }

      const totalEnrichment = baseEntries.length

      setImportPhase('enriching', {
        message: 'Enriching KEV entries with classification data',
        completed: 0,
        total: totalEnrichment
      })
      markTaskProgress('kev', 0, totalEnrichment, 'Enriching KEV entries')

      const enrichedResults = await mapWithConcurrency(
        baseEntries,
        CVELIST_ENRICHMENT_CONCURRENCY,
        async base => {
          const metrics = cvssMetrics.get(base.cveId)
          const enrichedBase: KevBaseEntry = {
            ...base,
            cvssScore: metrics?.score ?? null,
            cvssVector: metrics?.vector ?? null,
            cvssVersion: metrics?.version ?? null,
            cvssSeverity: metrics?.severity ?? null
          }

          let enrichmentResult: EnrichBaseEntryResult

          try {
            enrichmentResult = await enrichBaseEntryWithCvelist(enrichedBase)
          } catch {
            enrichmentResult = { entry: enrichedBase, impacts: [], hit: false }
          }

          const entry = enrichEntry(enrichmentResult.entry)
          return { entry, impacts: enrichmentResult.impacts, hit: enrichmentResult.hit }
        },
        {
          onProgress(completed, total) {
            if (total === 0) {
              return
            }
            updateImportProgress('enriching', completed, total)
            markTaskProgress('kev', completed, total)
          }
        }
      )

      await flushCvelistCache()

      let cvelistHits = 0
      let cvelistMisses = 0
      for (const result of enrichedResults) {
        if (result.hit) {
          cvelistHits += 1
        } else {
          cvelistMisses += 1
        }
      }

      if (cvelistHits > 0 || cvelistMisses > 0) {
        const message = `CVEList enrichment processed (${cvelistHits} hits, ${cvelistMisses} misses)`
        markTaskProgress('kev', 0, 0, message)
      }

      const entries = enrichedResults.map(result => result.entry)
      const impactRecordMap = new Map<string, VulnerabilityImpactRecord[]>()
      for (const result of enrichedResults) {
        if (result.impacts.length) {
          impactRecordMap.set(result.entry.id, result.impacts)
        }
      }

      const importedAt = new Date().toISOString()

      type EntryRowValues = {
        id: string
        cveId: string
        source: 'kev'
        vendor: string
        product: string
        vendorKey: string
        productKey: string
        vulnerabilityName: string
        description: string
        requiredAction: string | null
        dateAdded: string
        dueDate: string | null
        ransomwareUse: string | null
        notes: string
        cwes: string
        cvssScore: number | null
        cvssVector: string | null
        cvssVersion: string | null
        cvssSeverity: KevEntry['cvssSeverity']
        epssScore: number | null
        assigner: string | null
        datePublished: string | null
        dateUpdated: string | null
        exploitedSince: string | null
        sourceUrl: string | null
        pocUrl: string | null
        pocPublishedAt: string | null
        referenceLinks: string
        aliases: string
        affectedProducts: string
        problemTypes: string
        metasploitModulePath: string | null
        metasploitModulePublishedAt: string | null
        internetExposed: number
      }

      type CategoryRecord = {
        entryId: string
        categoryType: 'domain' | 'exploit' | 'vulnerability'
        value: string
        name: string
      }

      type ImpactRecord = {
        entryId: string
        vendor: string
        vendorKey: string
        product: string
        productKey: string
        status: string
        versionRange: string
        source: string
      }

      const createEntryValues = (entry: KevEntry): EntryRowValues => ({
        id: entry.id,
        cveId: entry.cveId,
        source: 'kev',
        vendor: entry.vendor,
        product: entry.product,
        vendorKey: entry.vendorKey,
        productKey: entry.productKey,
        vulnerabilityName: entry.vulnerabilityName,
        description: entry.description,
        requiredAction: entry.requiredAction,
        dateAdded: entry.dateAdded,
        dueDate: entry.dueDate,
        ransomwareUse: entry.ransomwareUse,
        notes: toJson(entry.notes),
        cwes: toJson(entry.cwes),
        cvssScore: entry.cvssScore,
        cvssVector: entry.cvssVector,
        cvssVersion: entry.cvssVersion,
        cvssSeverity: entry.cvssSeverity,
        epssScore: null,
        assigner: null,
        datePublished: entry.datePublished,
        dateUpdated: entry.dateUpdated,
        exploitedSince: entry.exploitedSince,
        sourceUrl: entry.sourceUrl ?? null,
        pocUrl: entry.pocUrl ?? null,
        pocPublishedAt: entry.pocPublishedAt ?? null,
        referenceLinks: toJson(entry.references),
        aliases: toJson(entry.aliases),
        affectedProducts: toJson(entry.affectedProducts),
        problemTypes: toJson(entry.problemTypes),
        metasploitModulePath: entry.metasploitModulePath,
        metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
        internetExposed: entry.internetExposed ? 1 : 0
      })

      const buildCategoryRecords = (entry: KevEntry): CategoryRecord[] => {
        const records: CategoryRecord[] = []
        const pushCategories = (values: string[], type: CategoryRecord['categoryType']) => {
          for (const value of values) {
            records.push({ entryId: entry.id, categoryType: type, value, name: value })
          }
        }
        pushCategories(entry.domainCategories, 'domain')
        pushCategories(entry.exploitLayers, 'exploit')
        pushCategories(entry.vulnerabilityCategories, 'vulnerability')
        return records
      }

      const normaliseImpacts = (impacts: VulnerabilityImpactRecord[]): ImpactRecord[] => {
        return impacts.map(impact => ({
          entryId: impact.entryId,
          vendor: impact.vendor,
          vendorKey: impact.vendorKey,
          product: impact.product,
          productKey: impact.productKey,
          status: impact.status ?? '',
          versionRange: impact.versionRange ?? '',
          source: impact.source
        }))
      }

      const sortImpacts = (records: ImpactRecord[]) => {
        return records
          .map(record => ({ ...record }))
          .sort((first, second) => {
            const firstKey = [first.vendorKey, first.productKey, first.status, first.versionRange, first.source].join('|')
            const secondKey = [second.vendorKey, second.productKey, second.status, second.versionRange, second.source].join('|')
            return firstKey.localeCompare(secondKey)
          })
      }

      const sortCategories = (records: CategoryRecord[]) => {
        return records
          .map(record => ({ ...record }))
          .sort((first, second) => {
            const firstKey = `${first.categoryType}|${first.value}`
            const secondKey = `${second.categoryType}|${second.value}`
            return firstKey.localeCompare(secondKey)
          })
      }

      const createRecordSignature = (
        values: EntryRowValues,
        impacts: ImpactRecord[],
        categories: CategoryRecord[]
      ) => {
        return JSON.stringify({
          values: { ...values },
          impacts: sortImpacts(impacts),
          categories: sortCategories(categories)
        })
      }

      type EntryDiffRecord = {
        values: EntryRowValues
        impacts: ImpactRecord[]
        categories: CategoryRecord[]
        signature: string
      }

      const entryRecords: EntryDiffRecord[] = entries.map(entry => {
        const values = createEntryValues(entry)
        const categories = buildCategoryRecords(entry)
        const impacts = normaliseImpacts(impactRecordMap.get(entry.id) ?? [])
        return {
          values,
          impacts,
          categories,
          signature: createRecordSignature(values, impacts, categories)
        }
      })

      const useIncrementalKev = strategy === 'incremental'
      const totalEntries = entryRecords.length

      if (!useIncrementalKev) {
        db.transaction(tx => {
          tx
            .delete(tables.vulnerabilityEntries)
            .where(eq(tables.vulnerabilityEntries.source, 'kev'))
            .run()

          setImportPhase('saving', {
            message: 'Saving entries to the local cache',
            completed: 0,
            total: totalEntries
          })
          markTaskProgress('kev', 0, totalEntries, 'Saving entries to the local cache')

          for (let index = 0; index < entryRecords.length; index += 1) {
            const record = entryRecords[index]

            tx.insert(tables.vulnerabilityEntries).values(record.values).run()

            if (record.impacts.length) {
              tx.insert(tables.vulnerabilityEntryImpacts).values(record.impacts).run()
            }

            if (record.categories.length) {
              tx.insert(tables.vulnerabilityEntryCategories).values(record.categories).run()
            }

            if ((index + 1) % 25 === 0 || index + 1 === totalEntries) {
              const message = `Saving entries to the local cache (${index + 1} of ${totalEntries})`
              setImportPhase('saving', {
                completed: index + 1,
                total: totalEntries,
                message
              })
              markTaskProgress('kev', index + 1, totalEntries, message)
            }
          }

          const metadataRows = [
            { key: 'dateReleased', value: parsed.data.dateReleased },
            { key: 'catalogVersion', value: parsed.data.catalogVersion },
            { key: 'entryCount', value: String(totalEntries) },
            { key: 'lastImportAt', value: importedAt },
            { key: 'kev.lastNewCount', value: String(totalEntries) },
            { key: 'kev.lastUpdatedCount', value: '0' },
            { key: 'kev.lastSkippedCount', value: '0' },
            { key: 'kev.lastRemovedCount', value: '0' },
            { key: 'kev.lastImportStrategy', value: 'full' }
          ]

          for (const record of metadataRows) {
            tx
              .insert(tables.kevMetadata)
              .values(record)
              .onConflictDoUpdate({
                target: tables.kevMetadata.key,
                set: { value: sql`excluded.value` }
              })
              .run()
          }
        })

        kevImported = totalEntries
        kevNewCount = totalEntries
        kevUpdatedCount = 0
        kevSkippedCount = 0
        kevRemovedCount = 0
        kevImportStrategy = 'full'
        catalogVersion = parsed.data.catalogVersion
        dateReleased = parsed.data.dateReleased
        importTimestamp = importedAt
        const summaryMessage = `Imported ${totalEntries.toLocaleString()} KEV entries`
        publishTaskEvent('kev', `${summaryMessage} (catalog size: ${totalEntries.toLocaleString()})`)
        markTaskComplete('kev', summaryMessage)
      } else {
        type ExistingEntryRow = {
          id: string
          cveId: string | null
          vendor: string | null
          product: string | null
          vendorKey: string | null
          productKey: string | null
          vulnerabilityName: string | null
          description: string | null
          requiredAction: string | null
          dateAdded: string | null
          dueDate: string | null
          ransomwareUse: string | null
          notes: string | null
          cwes: string | null
          cvssScore: number | null
          cvssVector: string | null
          cvssVersion: string | null
          cvssSeverity: string | null
          epssScore: number | null
          assigner: string | null
          datePublished: string | null
          dateUpdated: string | null
          exploitedSince: string | null
          sourceUrl: string | null
          pocUrl: string | null
          pocPublishedAt: string | null
          referenceLinks: string | null
          aliases: string | null
          affectedProducts: string | null
          problemTypes: string | null
          metasploitModulePath: string | null
          metasploitModulePublishedAt: string | null
          internetExposed: number | null
        }

        type ExistingImpactRow = ImpactRecord

        type ExistingCategoryRow = CategoryRecord

        const createEntryValuesFromRow = (row: ExistingEntryRow): EntryRowValues => ({
          id: row.id,
          cveId: row.cveId ?? '',
          source: 'kev',
          vendor: row.vendor ?? '',
          product: row.product ?? '',
          vendorKey: row.vendorKey ?? '',
          productKey: row.productKey ?? '',
          vulnerabilityName: row.vulnerabilityName ?? '',
          description: row.description ?? '',
          requiredAction: row.requiredAction ?? null,
          dateAdded: row.dateAdded ?? '',
          dueDate: row.dueDate ?? null,
          ransomwareUse: row.ransomwareUse ?? null,
          notes: row.notes ?? '[]',
          cwes: row.cwes ?? '[]',
          cvssScore: typeof row.cvssScore === 'number' ? row.cvssScore : null,
          cvssVector: row.cvssVector ?? null,
          cvssVersion: row.cvssVersion ?? null,
          cvssSeverity: normaliseStoredSeverity(row.cvssSeverity),
          epssScore: typeof row.epssScore === 'number' ? row.epssScore : null,
          assigner: row.assigner ?? null,
          datePublished: row.datePublished ?? null,
          dateUpdated: row.dateUpdated ?? null,
          exploitedSince: row.exploitedSince ?? null,
          sourceUrl: row.sourceUrl ?? null,
          pocUrl: row.pocUrl ?? null,
          pocPublishedAt: row.pocPublishedAt ?? null,
          referenceLinks: row.referenceLinks ?? '[]',
          aliases: row.aliases ?? '[]',
          affectedProducts: row.affectedProducts ?? '[]',
          problemTypes: row.problemTypes ?? '[]',
          metasploitModulePath: row.metasploitModulePath ?? null,
          metasploitModulePublishedAt: row.metasploitModulePublishedAt ?? null,
          internetExposed: typeof row.internetExposed === 'number' ? row.internetExposed : 0
        })

        const existingRows = db
          .select({
            id: tables.vulnerabilityEntries.id,
            cveId: tables.vulnerabilityEntries.cveId,
            vendor: tables.vulnerabilityEntries.vendor,
            product: tables.vulnerabilityEntries.product,
            vendorKey: tables.vulnerabilityEntries.vendorKey,
            productKey: tables.vulnerabilityEntries.productKey,
            vulnerabilityName: tables.vulnerabilityEntries.vulnerabilityName,
            description: tables.vulnerabilityEntries.description,
            requiredAction: tables.vulnerabilityEntries.requiredAction,
            dateAdded: tables.vulnerabilityEntries.dateAdded,
            dueDate: tables.vulnerabilityEntries.dueDate,
            ransomwareUse: tables.vulnerabilityEntries.ransomwareUse,
            notes: tables.vulnerabilityEntries.notes,
            cwes: tables.vulnerabilityEntries.cwes,
            cvssScore: tables.vulnerabilityEntries.cvssScore,
            cvssVector: tables.vulnerabilityEntries.cvssVector,
            cvssVersion: tables.vulnerabilityEntries.cvssVersion,
            cvssSeverity: tables.vulnerabilityEntries.cvssSeverity,
            epssScore: tables.vulnerabilityEntries.epssScore,
            assigner: tables.vulnerabilityEntries.assigner,
            datePublished: tables.vulnerabilityEntries.datePublished,
            dateUpdated: tables.vulnerabilityEntries.dateUpdated,
            exploitedSince: tables.vulnerabilityEntries.exploitedSince,
            sourceUrl: tables.vulnerabilityEntries.sourceUrl,
            pocUrl: tables.vulnerabilityEntries.pocUrl,
            pocPublishedAt: tables.vulnerabilityEntries.pocPublishedAt,
            referenceLinks: tables.vulnerabilityEntries.referenceLinks,
            aliases: tables.vulnerabilityEntries.aliases,
            affectedProducts: tables.vulnerabilityEntries.affectedProducts,
            problemTypes: tables.vulnerabilityEntries.problemTypes,
            metasploitModulePath: tables.vulnerabilityEntries.metasploitModulePath,
            metasploitModulePublishedAt: tables.vulnerabilityEntries.metasploitModulePublishedAt,
            internetExposed: tables.vulnerabilityEntries.internetExposed
          })
          .from(tables.vulnerabilityEntries)
          .where(eq(tables.vulnerabilityEntries.source, 'kev'))
          .all() as ExistingEntryRow[]

        const existingMap = new Map<string, { values: EntryRowValues; impacts: ImpactRecord[]; categories: CategoryRecord[]; signature: string }>()

        for (const row of existingRows) {
          existingMap.set(row.id, {
            values: createEntryValuesFromRow(row),
            impacts: [],
            categories: [],
            signature: ''
          })
        }

        const existingIds = Array.from(existingMap.keys())

        if (existingIds.length > 0) {
          const impactRows = db
            .select({
              entryId: tables.vulnerabilityEntryImpacts.entryId,
              vendor: tables.vulnerabilityEntryImpacts.vendor,
              vendorKey: tables.vulnerabilityEntryImpacts.vendorKey,
              product: tables.vulnerabilityEntryImpacts.product,
              productKey: tables.vulnerabilityEntryImpacts.productKey,
              status: tables.vulnerabilityEntryImpacts.status,
              versionRange: tables.vulnerabilityEntryImpacts.versionRange,
              source: tables.vulnerabilityEntryImpacts.source
            })
            .from(tables.vulnerabilityEntryImpacts)
            .where(inArray(tables.vulnerabilityEntryImpacts.entryId, existingIds))
            .all() as ExistingImpactRow[]

          for (const impact of impactRows) {
            const bucket = existingMap.get(impact.entryId)
            if (bucket) {
              bucket.impacts.push({
                entryId: impact.entryId,
                vendor: impact.vendor,
                vendorKey: impact.vendorKey,
                product: impact.product,
                productKey: impact.productKey,
                status: impact.status ?? '',
                versionRange: impact.versionRange ?? '',
                source: impact.source
              })
            }
          }

          const categoryRows = db
            .select({
              entryId: tables.vulnerabilityEntryCategories.entryId,
              categoryType: tables.vulnerabilityEntryCategories.categoryType,
              value: tables.vulnerabilityEntryCategories.value,
              name: tables.vulnerabilityEntryCategories.name
            })
            .from(tables.vulnerabilityEntryCategories)
            .where(inArray(tables.vulnerabilityEntryCategories.entryId, existingIds))
            .all() as ExistingCategoryRow[]

          for (const category of categoryRows) {
            const bucket = existingMap.get(category.entryId)
            if (bucket) {
              bucket.categories.push({
                entryId: category.entryId,
                categoryType: category.categoryType,
                value: category.value,
                name: category.name
              })
            }
          }

          for (const bucket of existingMap.values()) {
            bucket.signature = createRecordSignature(bucket.values, bucket.impacts, bucket.categories)
          }
        }

        const seenExisting = new Set<string>()
        const newRecords: EntryDiffRecord[] = []
        const updatedRecords: EntryDiffRecord[] = []
        const unchangedRecords: EntryDiffRecord[] = []

        for (const record of entryRecords) {
          const existing = existingMap.get(record.values.id)
          if (!existing) {
            newRecords.push(record)
            continue
          }

          seenExisting.add(record.values.id)

          if (existing.signature !== record.signature) {
            updatedRecords.push(record)
          } else {
            unchangedRecords.push(record)
          }
        }

        const removedIds = existingIds.filter(id => !seenExisting.has(id))
        const totalChanges = newRecords.length + updatedRecords.length

        db.transaction(tx => {
          if (totalChanges > 0) {
            const message = 'Saving KEV changes to the local cache'
            setImportPhase('saving', { message, completed: 0, total: totalChanges })
            markTaskProgress('kev', 0, totalChanges, message)
          } else if (removedIds.length > 0) {
            const message = `Removing ${removedIds.length.toLocaleString()} retired KEV entr${removedIds.length === 1 ? 'y' : 'ies'}`
            setImportPhase('saving', { message, completed: 0, total: 0 })
            markTaskProgress('kev', 0, 0, message)
          } else {
            const message = 'KEV catalog already up to date'
            setImportPhase('saving', { message, completed: 0, total: 0 })
            markTaskProgress('kev', 0, 0, message)
          }

          const persistRecord = (record: EntryDiffRecord, action: 'insert' | 'update', index: number) => {
            const { values, impacts, categories } = record

            if (action === 'insert') {
              tx.insert(tables.vulnerabilityEntries).values(values).run()
            } else {
              const { id, ...updateValues } = values
              tx
                .update(tables.vulnerabilityEntries)
                .set(updateValues)
                .where(eq(tables.vulnerabilityEntries.id, id))
                .run()
            }

            tx
              .delete(tables.vulnerabilityEntryImpacts)
              .where(eq(tables.vulnerabilityEntryImpacts.entryId, values.id))
              .run()

            if (impacts.length) {
              tx.insert(tables.vulnerabilityEntryImpacts).values(impacts).run()
            }

            tx
              .delete(tables.vulnerabilityEntryCategories)
              .where(eq(tables.vulnerabilityEntryCategories.entryId, values.id))
              .run()

            if (categories.length) {
              tx.insert(tables.vulnerabilityEntryCategories).values(categories).run()
            }

            if (totalChanges > 0) {
              const completed = index + 1
              const progressMessage = `Saving KEV changes to the local cache (${completed} of ${totalChanges})`
              setImportPhase('saving', { completed, total: totalChanges, message: progressMessage })
              markTaskProgress('kev', completed, totalChanges, progressMessage)
            }
          }

          let processed = 0
          for (const record of newRecords) {
            persistRecord(record, 'insert', processed)
            processed += 1
          }
          for (const record of updatedRecords) {
            persistRecord(record, 'update', processed)
            processed += 1
          }

          if (removedIds.length > 0) {
            tx
              .delete(tables.vulnerabilityEntries)
              .where(inArray(tables.vulnerabilityEntries.id, removedIds))
              .run()
          }

          const metadataRows = [
            { key: 'dateReleased', value: parsed.data.dateReleased },
            { key: 'catalogVersion', value: parsed.data.catalogVersion },
            { key: 'entryCount', value: String(totalEntries) },
            { key: 'lastImportAt', value: importedAt },
            { key: 'kev.lastNewCount', value: String(newRecords.length) },
            { key: 'kev.lastUpdatedCount', value: String(updatedRecords.length) },
            { key: 'kev.lastSkippedCount', value: String(unchangedRecords.length) },
            { key: 'kev.lastRemovedCount', value: String(removedIds.length) },
            { key: 'kev.lastImportStrategy', value: 'incremental' }
          ]

          for (const record of metadataRows) {
            tx
              .insert(tables.kevMetadata)
              .values(record)
              .onConflictDoUpdate({
                target: tables.kevMetadata.key,
                set: { value: sql`excluded.value` }
              })
              .run()
          }
        })

        kevImported = newRecords.length + updatedRecords.length
        kevNewCount = newRecords.length
        kevUpdatedCount = updatedRecords.length
        kevSkippedCount = unchangedRecords.length
        kevRemovedCount = removedIds.length
        kevImportStrategy = 'incremental'
        catalogVersion = parsed.data.catalogVersion
        dateReleased = parsed.data.dateReleased
        importTimestamp = importedAt

        const detailSegments: string[] = []
        if (newRecords.length > 0) {
          detailSegments.push(`${newRecords.length.toLocaleString()} new`)
        }
        if (updatedRecords.length > 0) {
          detailSegments.push(`${updatedRecords.length.toLocaleString()} updated`)
        }
        if (unchangedRecords.length > 0) {
          detailSegments.push(`${unchangedRecords.length.toLocaleString()} unchanged`)
        }
        if (removedIds.length > 0) {
          detailSegments.push(`${removedIds.length.toLocaleString()} removed`)
        }

        const detailSummary = detailSegments.length
          ? detailSegments.join(', ')
          : 'no changes detected'
        const summaryMessage = `Incremental KEV import: ${detailSummary} (catalog size: ${totalEntries.toLocaleString()})`
        publishTaskEvent('kev', summaryMessage)
        markTaskComplete('kev', summaryMessage)
      }
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : typeof error === 'string'
            ? error
            : 'KEV import failed'
      markTaskError('kev', message)
      throw error
    }
    }

    let historicSummary = {
      imported: 0,
      totalCount: 0,
      newCount: 0,
      updatedCount: 0,
      skippedCount: 0,
      removedCount: 0,
      strategy
    }
    if (shouldImport('historic')) {
      historicSummary = await importHistoricCatalog(db, { strategy })
      historicImported = historicSummary.imported
      historicNewCount = historicSummary.newCount
      historicUpdatedCount = historicSummary.updatedCount
      historicSkippedCount = historicSummary.skippedCount
      historicRemovedCount = historicSummary.removedCount
      historicImportStrategy = historicSummary.strategy
    } else {
      markTaskSkipped('historic', 'Skipped this run')
    }

    let enisaSummary = {
      imported: 0,
      totalCount: 0,
      newCount: 0,
      updatedCount: 0,
      skippedCount: 0,
      removedCount: 0,
      strategy,
      lastUpdated: enisaLastUpdated ?? null
    }
    if (shouldImport('enisa')) {
      enisaSummary = await importEnisaCatalog(db, {
        ttlMs: ONE_DAY_MS,
        forceRefresh,
        allowStale,
        strategy
      })
      enisaImported = enisaSummary.imported
      enisaNewCount = enisaSummary.newCount
      enisaUpdatedCount = enisaSummary.updatedCount
      enisaSkippedCount = enisaSummary.skippedCount
      enisaRemovedCount = enisaSummary.removedCount
      enisaImportStrategy = enisaSummary.strategy
      enisaLastUpdated = enisaSummary.lastUpdated ?? enisaLastUpdated ?? null
    } else {
      markTaskSkipped('enisa', 'Skipped this run')
    }

    let metasploitSummary = {
      imported: 0,
      totalCount: 0,
      newCount: 0,
      updatedCount: 0,
      skippedCount: 0,
      removedCount: 0,
      strategy,
      commit: metasploitCommit,
      modules: metasploitModules
    }
    if (shouldImport('metasploit')) {
      metasploitSummary = await importMetasploitCatalog(db, {
        useCachedRepository: allowStale,
        offline: allowStale,
        reprocessCachedEntries: allowStale,
        strategy
      })
      metasploitImported = metasploitSummary.imported
      metasploitCommit = metasploitSummary.commit ?? metasploitCommit
      metasploitModules = metasploitSummary.modules
      metasploitNewCount = metasploitSummary.newCount
      metasploitUpdatedCount = metasploitSummary.updatedCount
      metasploitSkippedCount = metasploitSummary.skippedCount
      metasploitRemovedCount = metasploitSummary.removedCount
      metasploitImportStrategy = metasploitSummary.strategy
    } else {
      markTaskSkipped('metasploit', 'Skipped this run')
    }

    let pocSummary = {
      imported: 0,
      totalCount: 0,
      newCount: 0,
      updatedCount: 0,
      skippedCount: 0,
      removedCount: 0,
      strategy,
      cachedAt: null as string | null
    }
    if (shouldImport('poc')) {
      pocSummary = await importGithubPocCatalog(db, {
        ttlMs: ONE_DAY_MS,
        forceRefresh,
        allowStale,
        strategy
      })
      pocImported = pocSummary.imported
      pocNewCount = pocSummary.newCount
      pocUpdatedCount = pocSummary.updatedCount
      pocSkippedCount = pocSummary.skippedCount
      pocRemovedCount = pocSummary.removedCount
      pocImportStrategy = pocSummary.strategy
    } else {
      markTaskSkipped('poc', 'Skipped this run')
    }

    let marketSummary = {
      imported: 0,
      offerCount: 0,
      programCount: 0,
      productCount: 0,
      lastCaptureAt: null as string | null,
      lastSnapshotAt: null as string | null
    }
    if (shouldImport('market')) {
      marketSummary = await importMarketIntel(db, { forceRefresh, allowStale })
      marketImported = marketSummary.imported
      marketOfferCount = marketSummary.offerCount
      marketProgramCount = marketSummary.programCount
      marketProductCount = marketSummary.productCount
      marketLastCaptureAt = marketSummary.lastCaptureAt
      marketLastSnapshotAt = marketSummary.lastSnapshotAt
    } else {
      markTaskSkipped('market', 'Skipped this run')
    }

    const catalogSummary = rebuildCatalog(db)
    rebuildProductCatalog(db)

    const totalImported =
      kevImported +
      historicImported +
      enisaImported +
      metasploitImported +
      pocImported +
      marketImported

    const segments: string[] = []
    if (shouldImport('kev')) {
      if (kevImportStrategy === 'incremental') {
        const kevSegments: string[] = []
        if (kevNewCount > 0) {
          kevSegments.push(`${kevNewCount.toLocaleString()} new`)
        }
        if (kevUpdatedCount > 0) {
          kevSegments.push(`${kevUpdatedCount.toLocaleString()} updated`)
        }
        if (kevSkippedCount > 0) {
          kevSegments.push(`${kevSkippedCount.toLocaleString()} unchanged`)
        }
        if (kevRemovedCount > 0) {
          kevSegments.push(`${kevRemovedCount.toLocaleString()} removed`)
        }
        const kevDetail = kevSegments.length ? ` (${kevSegments.join(', ')})` : ''
        segments.push(`${kevImported.toLocaleString()} CISA KEV entries${kevDetail}`)
      } else {
        segments.push(`${kevImported.toLocaleString()} CISA KEV entries`)
      }
    }
    if (shouldImport('historic')) {
      if (historicImportStrategy === 'incremental') {
        const historicSegments: string[] = []
        if (historicNewCount > 0) {
          historicSegments.push(`${historicNewCount.toLocaleString()} new`)
        }
        if (historicUpdatedCount > 0) {
          historicSegments.push(`${historicUpdatedCount.toLocaleString()} updated`)
        }
        if (historicSkippedCount > 0) {
          historicSegments.push(`${historicSkippedCount.toLocaleString()} unchanged`)
        }
        if (historicRemovedCount > 0) {
          historicSegments.push(`${historicRemovedCount.toLocaleString()} removed`)
        }
        const detail = historicSegments.length ? ` (${historicSegments.join(', ')})` : ''
        segments.push(`${historicImported.toLocaleString()} historic entries${detail}`)
      } else {
        segments.push(`${historicImported.toLocaleString()} historic entries`)
      }
    }
    if (shouldImport('enisa')) {
      if (enisaImportStrategy === 'incremental') {
        const enisaSegments: string[] = []
        if (enisaNewCount > 0) {
          enisaSegments.push(`${enisaNewCount.toLocaleString()} new`)
        }
        if (enisaUpdatedCount > 0) {
          enisaSegments.push(`${enisaUpdatedCount.toLocaleString()} updated`)
        }
        if (enisaSkippedCount > 0) {
          enisaSegments.push(`${enisaSkippedCount.toLocaleString()} unchanged`)
        }
        if (enisaRemovedCount > 0) {
          enisaSegments.push(`${enisaRemovedCount.toLocaleString()} removed`)
        }
        const detail = enisaSegments.length ? ` (${enisaSegments.join(', ')})` : ''
        segments.push(`${enisaImported.toLocaleString()} ENISA entries${detail}`)
      } else {
        segments.push(`${enisaImported.toLocaleString()} ENISA entries`)
      }
    }
    if (shouldImport('metasploit')) {
      if (metasploitImportStrategy === 'incremental') {
        const metasploitSegments: string[] = []
        if (metasploitNewCount > 0) {
          metasploitSegments.push(`${metasploitNewCount.toLocaleString()} new`)
        }
        if (metasploitUpdatedCount > 0) {
          metasploitSegments.push(`${metasploitUpdatedCount.toLocaleString()} updated`)
        }
        if (metasploitSkippedCount > 0) {
          metasploitSegments.push(`${metasploitSkippedCount.toLocaleString()} unchanged`)
        }
        if (metasploitRemovedCount > 0) {
          metasploitSegments.push(`${metasploitRemovedCount.toLocaleString()} removed`)
        }
        const detail = metasploitSegments.length ? ` (${metasploitSegments.join(', ')})` : ''
        const base = `${metasploitImported.toLocaleString()} Metasploit entries${detail}`
        const withModules =
          metasploitModules > 0
            ? `${base} across ${metasploitModules.toLocaleString()} modules`
            : base
        segments.push(withModules)
      } else {
        const base = `${metasploitImported.toLocaleString()} Metasploit entries`
        const withModules =
          metasploitModules > 0
            ? `${base} across ${metasploitModules.toLocaleString()} modules`
            : base
        segments.push(withModules)
      }
    }
    if (shouldImport('poc')) {
      if (pocImportStrategy === 'incremental') {
        const pocSegments: string[] = []
        if (pocNewCount > 0) {
          pocSegments.push(`${pocNewCount.toLocaleString()} new`)
        }
        if (pocUpdatedCount > 0) {
          pocSegments.push(`${pocUpdatedCount.toLocaleString()} updated`)
        }
        if (pocSkippedCount > 0) {
          pocSegments.push(`${pocSkippedCount.toLocaleString()} unchanged`)
        }
        if (pocRemovedCount > 0) {
          pocSegments.push(`${pocRemovedCount.toLocaleString()} removed`)
        }
        const detail = pocSegments.length ? ` (${pocSegments.join(', ')})` : ''
        segments.push(`${pocImported.toLocaleString()} GitHub PoC entries${detail}`)
      } else {
        segments.push(`${pocImported.toLocaleString()} GitHub PoC entries`)
      }
    }
    if (shouldImport('market')) {
      const base = `${marketOfferCount.toLocaleString()} market intelligence offers`
      const extras: string[] = []
      if (marketProgramCount > 0) {
        extras.push(`${marketProgramCount.toLocaleString()} programs`)
      }
      if (marketProductCount > 0) {
        extras.push(`${marketProductCount.toLocaleString()} matched products`)
      }
      if (extras.length === 0) {
        segments.push(base)
      } else {
        const scopeLabel =
          extras.length === 1
            ? extras[0]
            : `${extras.slice(0, -1).join(', ')} and ${extras[extras.length - 1]}`
        segments.push(`${base} across ${scopeLabel}`)
      }
    }

    const progressMessage = segments.length
      ? `Imported ${segments.join(', ')} (catalog size: ${catalogSummary.count})`
      : `Catalog refresh complete (catalog size: ${catalogSummary.count})`

    completeImportProgress(progressMessage)

    return {
      imported: totalImported,
      kevImported,
      kevNewCount,
      kevUpdatedCount,
      kevSkippedCount,
      kevRemovedCount,
      kevImportStrategy,
      historicImported: historicSummary.imported,
      historicNewCount,
      historicUpdatedCount,
      historicSkippedCount,
      historicRemovedCount,
      historicImportStrategy,
      enisaImported: enisaSummary.imported,
      enisaNewCount,
      enisaUpdatedCount,
      enisaSkippedCount,
      enisaRemovedCount,
      enisaImportStrategy,
      metasploitImported: metasploitSummary.imported,
      metasploitNewCount,
      metasploitUpdatedCount,
      metasploitSkippedCount,
      metasploitRemovedCount,
      metasploitImportStrategy,
      metasploitModules: metasploitSummary.modules,
      metasploitCommit: metasploitSummary.commit,
      pocImported: pocSummary.imported,
      pocNewCount,
      pocUpdatedCount,
      pocSkippedCount,
      pocRemovedCount,
      pocImportStrategy,
      marketImported: marketSummary.imported,
      marketOfferCount: marketSummary.offerCount,
      marketProgramCount: marketSummary.programCount,
      marketProductCount: marketSummary.productCount,
      marketLastCaptureAt: marketSummary.lastCaptureAt,
      marketLastSnapshotAt: marketSummary.lastSnapshotAt,
      dateReleased,
      catalogVersion,
      enisaLastUpdated,
      importedAt: importTimestamp,
      sources: sourcesToImport
    }
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Vulnerability catalog import failed'
    failImportProgress(message)
    throw error
  }
})
