import { createError, readBody } from 'h3'
import { ofetch } from 'ofetch'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import type { ImportTaskKey, KevEntry } from '~/types'
import { eq, sql } from 'drizzle-orm'
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
  setImportPhase,
  startImportProgress,
  updateImportProgress
} from '../utils/import-progress'
import { rebuildCatalog } from '../utils/catalog'
import { getDatabase, getMetadata } from '../utils/sqlite'
import { tables } from '../database/client'
import { rebuildProductCatalog } from '../utils/product-catalog'
import { importMetasploitCatalog } from '../utils/metasploit'

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

const toJson = (value: string[] | undefined | null): string => JSON.stringify(value ?? [])

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

const IMPORT_SOURCE_ORDER: ImportTaskKey[] = ['kev', 'historic', 'enisa', 'metasploit']

const isImportSourceKey = (value: string): value is ImportTaskKey => {
  return IMPORT_SOURCE_ORDER.includes(value as ImportTaskKey)
}

export default defineEventHandler(async event => {
  const body = await readBody<{ mode?: ImportMode; source?: string }>(event).catch(
    () => ({}) as { mode?: ImportMode; source?: string }
  )

  const mode = body?.mode ?? 'auto'
  const forceRefresh = mode === 'force'
  const allowStale = mode === 'cache'
  const rawSource = typeof body?.source === 'string' ? body.source.toLowerCase() : 'all'

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
  let historicImported = 0
  let enisaImported = 0
  let metasploitImported = 0

  const db = getDatabase()

  try {
    if (!shouldImport('kev')) {
      markTaskSkipped('kev', 'Skipped this run')
    } else {
      markTaskRunning('kev', 'Checking KEV cache')

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
          const normalised = normaliseVendorProduct({
            vendor: item.vendorProject,
            product: item.product
          })
          return {
            id: `kev:${cveId}`,
            sources: ['kev'],
            cveId,
            vendor: normalised.vendor.label,
            vendorKey: normalised.vendor.key,
            product: normalised.product.label,
            productKey: normalised.product.key,
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

      setImportPhase('enriching', { message: 'Enriching KEV entries with classification data' })
      markTaskProgress('kev', 0, baseEntries.length, 'Enriching KEV entries')

      const entries = baseEntries.map(base => {
        const metrics = cvssMetrics.get(base.cveId)
        const enrichedBase: KevBaseEntry = {
          ...base,
          cvssScore: metrics?.score ?? null,
          cvssVector: metrics?.vector ?? null,
          cvssVersion: metrics?.version ?? null,
          cvssSeverity: metrics?.severity ?? null
        }

        return enrichEntry(enrichedBase)
      })

      const importedAt = new Date().toISOString()

      db.transaction(tx => {
        tx
          .delete(tables.vulnerabilityEntries)
          .where(eq(tables.vulnerabilityEntries.source, 'kev'))
          .run()

        setImportPhase('saving', {
          message: 'Saving entries to the local cache',
          completed: 0,
          total: entries.length
        })
        markTaskProgress('kev', 0, entries.length, 'Saving entries to the local cache')

        for (let index = 0; index < entries.length; index += 1) {
          const entry = entries[index]
          const entryId = entry.id

          tx
            .insert(tables.vulnerabilityEntries)
            .values({
              id: entryId,
              cveId: entry.cveId,
              source: 'kev',
              vendor: entry.vendor,
              product: entry.product,
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
              referenceLinks: toJson(entry.references),
              aliases: toJson(entry.aliases),
              metasploitModulePath: entry.metasploitModulePath,
              metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
              internetExposed: entry.internetExposed ? 1 : 0
            })
            .run()

          const dimensionRecords: Array<{
            entryId: string
            categoryType: string
            value: string
            name: string
          }> = []

          const pushCategories = (values: string[], type: 'domain' | 'exploit' | 'vulnerability') => {
            for (const value of values) {
              dimensionRecords.push({ entryId, categoryType: type, value, name: value })
            }
          }

          pushCategories(entry.domainCategories, 'domain')
          pushCategories(entry.exploitLayers, 'exploit')
          pushCategories(entry.vulnerabilityCategories, 'vulnerability')

          if (dimensionRecords.length) {
            tx.insert(tables.vulnerabilityEntryCategories).values(dimensionRecords).run()
          }

          if ((index + 1) % 25 === 0 || index + 1 === entries.length) {
            const message = `Saving entries to the local cache (${index + 1} of ${entries.length})`
            setImportPhase('saving', {
              completed: index + 1,
              total: entries.length,
              message
            })
            markTaskProgress('kev', index + 1, entries.length, message)
          }
        }

        const metadataRows = [
          { key: 'dateReleased', value: parsed.data.dateReleased },
          { key: 'catalogVersion', value: parsed.data.catalogVersion },
          { key: 'entryCount', value: String(entries.length) },
          { key: 'lastImportAt', value: importedAt }
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

      kevImported = entries.length
      catalogVersion = parsed.data.catalogVersion
      dateReleased = parsed.data.dateReleased
      importTimestamp = importedAt
      markTaskComplete('kev', `Imported ${entries.length.toLocaleString()} KEV entries`)
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

    let historicSummary = { imported: 0 }
    if (shouldImport('historic')) {
      historicSummary = await importHistoricCatalog(db)
      historicImported = historicSummary.imported
    } else {
      markTaskSkipped('historic', 'Skipped this run')
    }

    let enisaSummary = { imported: 0, lastUpdated: enisaLastUpdated ?? null }
    if (shouldImport('enisa')) {
      enisaSummary = await importEnisaCatalog(db, { ttlMs: ONE_DAY_MS, forceRefresh, allowStale })
      enisaImported = enisaSummary.imported
      enisaLastUpdated = enisaSummary.lastUpdated ?? enisaLastUpdated ?? null
    } else {
      markTaskSkipped('enisa', 'Skipped this run')
    }

    let metasploitSummary = { imported: 0, commit: metasploitCommit, modules: metasploitModules }
    if (shouldImport('metasploit')) {
      metasploitSummary = await importMetasploitCatalog(db, { useCachedRepository: allowStale })
      metasploitImported = metasploitSummary.imported
      metasploitCommit = metasploitSummary.commit ?? metasploitCommit
      metasploitModules = metasploitSummary.modules
    } else {
      markTaskSkipped('metasploit', 'Skipped this run')
    }

    const catalogSummary = rebuildCatalog(db)
    rebuildProductCatalog(db)

    const totalImported = kevImported + historicImported + enisaImported + metasploitImported

    const segments: string[] = []
    if (shouldImport('kev')) {
      segments.push(`${kevImported.toLocaleString()} CISA KEV entries`)
    }
    if (shouldImport('historic')) {
      segments.push(`${historicImported.toLocaleString()} historic entries`)
    }
    if (shouldImport('enisa')) {
      segments.push(`${enisaImported.toLocaleString()} ENISA entries`)
    }
    if (shouldImport('metasploit')) {
      const base = `${metasploitImported.toLocaleString()} Metasploit entries`
      const withModules =
        metasploitModules > 0
          ? `${base} across ${metasploitModules.toLocaleString()} modules`
          : base
      segments.push(withModules)
    }

    const progressMessage = segments.length
      ? `Imported ${segments.join(', ')} (catalog size: ${catalogSummary.count})`
      : `Catalog refresh complete (catalog size: ${catalogSummary.count})`

    completeImportProgress(progressMessage)

    return {
      imported: totalImported,
      kevImported,
      historicImported: historicSummary.imported,
      enisaImported: enisaSummary.imported,
      metasploitImported: metasploitSummary.imported,
      metasploitModules: metasploitSummary.modules,
      metasploitCommit: metasploitSummary.commit,
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
