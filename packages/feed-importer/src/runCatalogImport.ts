import { ofetch } from 'ofetch'
import { z } from 'zod'
import { eq, inArray, like, sql } from 'drizzle-orm'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import type { ImportTaskKey, KevEntry } from '~/types'
import type { ImportStrategy } from 'server/utils/import-types'
import { getCachedData } from 'server/utils/cache'
import { fetchCvssMetrics } from 'server/utils/cvss'
import { importEnisaCatalog } from 'server/utils/enisa'
import { importHistoricCatalog } from 'server/utils/historic'
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
} from 'server/utils/import-progress'
import { rebuildCatalog } from 'server/utils/catalog'
import { getMetadataMap } from 'server/utils/metadata'
import { tables } from 'server/database/client'
import type { DrizzleDatabase } from 'server/database/client'
import { rebuildProductCatalog } from 'server/utils/product-catalog'
import { importMetasploitCatalog } from 'server/utils/metasploit'
import { importGithubPocCatalog } from 'server/utils/github-poc'
import { importMarketIntel } from 'server/utils/market'
import {
  CVELIST_ENRICHMENT_CONCURRENCY,
  clearCvelistMemoryCache,
  enrichBaseEntryWithCvelist,
  flushCvelistCache,
  syncCvelistRepo,
  type EnrichBaseEntryResult,
  type VulnerabilityImpactRecord
} from 'server/utils/cvelist'
import { mapWithConcurrency } from 'server/utils/concurrency'
import {
  buildEntryDiffRecords,
  diffEntryRecords,
  insertCategoryRecords,
  insertImpactRecords,
  loadExistingEntryRecords,
  persistEntryRecord,
  type EntryDiffRecord
} from 'server/utils/entry-diff'

const ONE_DAY_MS = 86_400_000

export type CatalogImportMode = 'auto' | 'force' | 'cache'

export class CatalogImportError extends Error {
  statusCode?: number
  details?: unknown

  constructor(message: string, options: { statusCode?: number; details?: unknown } = {}) {
    super(message)
    this.name = 'CatalogImportError'
    this.statusCode = options.statusCode
    this.details = options.details
  }
}

export type CatalogImportOptions = {
  db: DrizzleDatabase
  sources: ImportTaskKey[]
  forceRefresh: boolean
  allowStale: boolean
  strategy: ImportStrategy
}

export type CatalogImportResult = {
  imported: number
  kevImported: number
  kevNewCount: number
  kevUpdatedCount: number
  kevSkippedCount: number
  kevRemovedCount: number
  kevImportStrategy: ImportStrategy
  kevNewCveIds: string[]
  historicImported: number
  historicNewCount: number
  historicUpdatedCount: number
  historicSkippedCount: number
  historicRemovedCount: number
  historicImportStrategy: ImportStrategy
  enisaImported: number
  enisaNewCount: number
  enisaUpdatedCount: number
  enisaSkippedCount: number
  enisaRemovedCount: number
  enisaImportStrategy: ImportStrategy
  metasploitImported: number
  metasploitNewCount: number
  metasploitUpdatedCount: number
  metasploitSkippedCount: number
  metasploitRemovedCount: number
  metasploitImportStrategy: ImportStrategy
  metasploitModules: number
  metasploitCommit: string | null
  pocImported: number
  pocNewCount: number
  pocUpdatedCount: number
  pocSkippedCount: number
  pocRemovedCount: number
  pocImportStrategy: ImportStrategy
  marketImported: number
  marketOfferCount: number
  marketProgramCount: number
  marketProductCount: number
  marketLastCaptureAt: string | null
  marketLastSnapshotAt: string | null
  dateReleased: string
  catalogVersion: string
  enisaLastUpdated: string | null
  importedAt: string
  sources: ImportTaskKey[]
}

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

export const IMPORT_SOURCE_ORDER: ImportTaskKey[] = [
  'kev',
  'historic',
  'enisa',
  'metasploit',
  'poc',
  'market'
]

export const isImportSourceKey = (value: string): value is ImportTaskKey => {
  return IMPORT_SOURCE_ORDER.includes(value as ImportTaskKey)
}

export const runCatalogImport = async (
  options: CatalogImportOptions
): Promise<CatalogImportResult> => {
  const { db, sources, forceRefresh, allowStale, strategy } = options

  if (allowStale) {
    clearCvelistMemoryCache()
  }

  startImportProgress('Starting vulnerability catalog import', sources)

  const shouldImport = (key: ImportTaskKey) => sources.includes(key)

  const metadata = await getMetadataMap([
    'catalogVersion',
    'dateReleased',
    'enisa.lastUpdatedAt',
    'metasploit.lastCommit',
    'metasploit.moduleCount'
  ])

  const fallbackCatalogVersion = metadata.catalogVersion ?? ''
  const fallbackDateReleased = metadata.dateReleased ?? ''
  const fallbackEnisaUpdated = metadata['enisa.lastUpdatedAt']
  const fallbackMetasploitCommit = metadata['metasploit.lastCommit']
  const fallbackMetasploitModules =
    Number.parseInt(metadata['metasploit.moduleCount'] ?? '0', 10) || 0

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
  let kevNewCveIds: string[] = []
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
          throw new CatalogImportError('Unable to parse KEV feed', {
            statusCode: 502,
            details: parsed.error.flatten()
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
        const existingRows: ExistingCvssRow[] = await db
          .select({
            cve_id: tables.vulnerabilityEntries.cveId,
            cvss_score: tables.vulnerabilityEntries.cvssScore,
            cvss_vector: tables.vulnerabilityEntries.cvssVector,
            cvss_version: tables.vulnerabilityEntries.cvssVersion,
            cvss_severity: tables.vulnerabilityEntries.cvssSeverity
          })
          .from(tables.vulnerabilityEntries)
          .where(eq(tables.vulnerabilityEntries.source, 'kev'))
          .all()

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

      const entryRecords = buildEntryDiffRecords(entries, 'kev', impactRecordMap)

      const useIncrementalKev = strategy === 'incremental'
      const totalEntries = entryRecords.length

      if (!useIncrementalKev) {
        // Clear any lingering KEV impact/category rows before rebuilding the source data.
        await db
          .delete(tables.vulnerabilityEntryImpacts)
          .where(like(tables.vulnerabilityEntryImpacts.entryId, 'kev:%'))
          .run()

        await db
          .delete(tables.vulnerabilityEntryCategories)
          .where(like(tables.vulnerabilityEntryCategories.entryId, 'kev:%'))
          .run()

        await db
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

          await db.insert(tables.vulnerabilityEntries).values(record.values).run()

          if (record.impacts.length) {
            await insertImpactRecords(db, record.impacts)
          }

          if (record.categories.length) {
            await insertCategoryRecords(db, record.categories)
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
          await db
            .insert(tables.kevMetadata)
            .values(record)
            .onConflictDoUpdate({
              target: tables.kevMetadata.key,
              set: { value: sql`excluded.value` }
            })
            .run()
        }

        kevImported = totalEntries
        kevNewCount = totalEntries
        kevUpdatedCount = 0
        kevSkippedCount = 0
        kevRemovedCount = 0
        kevImportStrategy = 'full'
        kevNewCveIds = entryRecords.map(record => record.values.cveId)
        catalogVersion = parsed.data.catalogVersion
        dateReleased = parsed.data.dateReleased
        importTimestamp = importedAt
        const summaryMessage = `Imported ${totalEntries.toLocaleString()} KEV entries`
        publishTaskEvent('kev', `${summaryMessage} (catalog size: ${totalEntries.toLocaleString()})`)
        markTaskComplete('kev', summaryMessage)
      } else {
        const existingMap = await loadExistingEntryRecords(db, 'kev')
        const { newRecords, updatedRecords, unchangedRecords, removedIds } =
          diffEntryRecords(entryRecords, existingMap)
        const totalChanges = newRecords.length + updatedRecords.length
        const unchangedCount = unchangedRecords.length
        const newKevIds = newRecords.map(record => record.values.cveId)

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

        let processed = 0
        db.transaction(tx => {
          const persistWithProgress = (
            record: EntryDiffRecord,
            action: 'insert' | 'update'
          ) => {
            persistEntryRecord(tx, record, action)

            if (totalChanges > 0) {
              processed += 1
              const progressMessage = `Saving KEV changes to the local cache (${processed} of ${totalChanges})`
              setImportPhase('saving', {
                completed: processed,
                total: totalChanges,
                message: progressMessage
              })
              markTaskProgress('kev', processed, totalChanges, progressMessage)
            }
          }

          for (const record of newRecords) {
            persistWithProgress(record, 'insert')
          }

          for (const record of updatedRecords) {
            persistWithProgress(record, 'update')
          }

          if (removedIds.length > 0) {
            const chunkSize = 25
            for (let index = 0; index < removedIds.length; index += chunkSize) {
              const idChunk = removedIds.slice(index, index + chunkSize)
              tx
                .delete(tables.vulnerabilityEntries)
                .where(inArray(tables.vulnerabilityEntries.id, idChunk))
                .run()
            }
          }

          const metadataRows = [
            { key: 'dateReleased', value: parsed.data.dateReleased },
            { key: 'catalogVersion', value: parsed.data.catalogVersion },
            { key: 'entryCount', value: String(totalEntries) },
            { key: 'lastImportAt', value: importedAt },
            { key: 'kev.lastNewCount', value: String(newRecords.length) },
            { key: 'kev.lastUpdatedCount', value: String(updatedRecords.length) },
            { key: 'kev.lastSkippedCount', value: String(unchangedCount) },
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
        kevSkippedCount = unchangedCount
        kevRemovedCount = removedIds.length
        kevImportStrategy = 'incremental'
        kevNewCveIds = newKevIds
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
        if (unchangedCount > 0) {
          detailSegments.push(`${unchangedCount.toLocaleString()} unchanged`)
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
        forceRefresh: forceRefresh || (strategy === 'incremental' && !allowStale),
        allowStale,
        strategy,
        lastKnownUpdatedAt: enisaLastUpdated ?? null
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

    const catalogSummary = await rebuildCatalog(db)
    await rebuildProductCatalog(db)

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
      kevNewCveIds,
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
      sources
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
}
