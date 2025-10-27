import { eq, inArray } from 'drizzle-orm'
import { ofetch } from 'ofetch'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'
import { setMetadata } from './sqlite'
import { getCachedData } from './cache'
import { mapWithConcurrency } from './concurrency'
import {
  CVELIST_ENRICHMENT_CONCURRENCY,
  enrichBaseEntryWithCvelist,
  flushCvelistCache,
  type VulnerabilityImpactRecord
} from './cvelist'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase,
  updateImportProgress
} from './import-progress'
import { resolvePocPublishDates } from './github-poc-history'
import {
  buildEntryDiffRecords,
  diffEntryRecords,
  loadExistingEntryRecords,
  persistEntryRecord
} from './entry-diff'
import type { ImportStrategy } from './import-types'

const POC_ENRICHMENT_CONCURRENCY = Math.max(16, CVELIST_ENRICHMENT_CONCURRENCY)
const POC_HISTORY_LOOKBACK_DAYS = 365

const SOURCE_URL = 'https://raw.githubusercontent.com/0xMarcio/cve/main/docs/CVE_list.json'
const SOURCE_REPO_URL = 'https://github.com/0xMarcio/cve/tree/main'
const CACHE_KEY = 'github-poc-feed'

const pocEntrySchema = z.object({
  cve: z.string(),
  desc: z.string().optional(),
  poc: z.array(z.string()).default([])
})

const pocDatasetSchema = z.array(pocEntrySchema)

const normaliseLinks = (links: string[]): string[] => {
  const seen = new Set<string>()
  const result: string[] = []

  for (const raw of links) {
    if (typeof raw !== 'string') {
      continue
    }

    const trimmed = raw.trim()
    if (!trimmed) {
      continue
    }

    if (!/^https?:\/\//i.test(trimmed)) {
      continue
    }

    if (seen.has(trimmed)) {
      continue
    }

    seen.add(trimmed)
    result.push(trimmed)
  }

  return result
}

const cvePattern = /cve-\d{4}-\d{4,}/i

const filterMeaningfulPocLinks = (cveId: string, links: string[]): string[] => {
  const lowerCve = cveId.toLowerCase()
  return links.filter(link => {
    try {
      const url = new URL(link)
      const host = url.hostname.toLowerCase()
      if (host === 'github.com' || host.endsWith('.github.com')) {
        const path = url.pathname.toLowerCase()
        const search = url.search.toLowerCase()
        if (path.includes(lowerCve) || search.includes(lowerCve)) {
          return true
        }
        return cvePattern.test(path)
      }
      return true
    } catch {
      return false
    }
  })
}

const toBaseEntry = (
  item: z.infer<typeof pocEntrySchema>,
  datasetTimestamp: string
): KevBaseEntry | null => {
  const cveId = item.cve?.trim().toUpperCase()
  if (!cveId) {
    return null
  }

  const pocLinks = normaliseLinks(item.poc ?? [])
  if (!pocLinks.length) {
    return null
  }

  const filteredLinks = filterMeaningfulPocLinks(cveId, pocLinks)
  if (!filteredLinks.length) {
    return null
  }

  const description = item.desc?.trim() ?? ''
  const primaryPocUrl = filteredLinks[0] ?? null
  const normalised = normaliseVendorProduct(
    { vendor: undefined, product: undefined },
    undefined,
    undefined,
    {
      vulnerabilityName: description || `Proof of concept available for ${cveId}`,
      description,
      cveId
    }
  )

  const references = Array.from(new Set([...filteredLinks, SOURCE_REPO_URL]))

  return {
    id: `poc:${cveId}`,
    sources: ['poc'],
    cveId,
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    affectedProducts: [],
    problemTypes: [],
    vulnerabilityName: description || `Proof of concept available for ${cveId}`,
    description,
    requiredAction: null,
    dateAdded: datasetTimestamp,
    dueDate: null,
    ransomwareUse: null,
    notes: [],
    cwes: [],
    cvssScore: null,
    cvssVector: null,
    cvssVersion: null,
    cvssSeverity: null,
    epssScore: null,
    assigner: null,
    datePublished: null,
    dateUpdated: null,
    exploitedSince: null,
    sourceUrl: primaryPocUrl ?? SOURCE_REPO_URL,
    pocUrl: primaryPocUrl,
    references,
    aliases: [cveId],
    metasploitModulePath: null,
    metasploitModulePublishedAt: null,
    internetExposed: false,
    pocPublishedAt: null
  }
}

type ImportOptions = {
  ttlMs?: number
  forceRefresh?: boolean
  allowStale?: boolean
  strategy?: ImportStrategy
}

type PocImportSummary = {
  imported: number
  totalCount: number
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: ImportStrategy
  cachedAt: string | null
}

const resolveDateAdded = (entry: KevBaseEntry, fallback: string): string => {
  const candidates = [
    entry.pocPublishedAt,
    entry.exploitedSince,
    entry.datePublished,
    entry.dateUpdated,
    entry.dateAdded,
    fallback
  ]

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate
    }
  }

  return ''
}

export const importGithubPocCatalog = async (
  db: DrizzleDatabase,
  options: ImportOptions = {}
): Promise<PocImportSummary> => {
  const ttlMs = options.ttlMs ?? 86_400_000
  const strategy = options.strategy ?? 'full'

  try {
    markTaskRunning('poc', 'Checking GitHub PoC feed cache')
    setImportPhase('fetchingPoc', {
      message: 'Checking GitHub PoC feed cache',
      completed: 0,
      total: 0
    })

    const dataset = await getCachedData(
      CACHE_KEY,
      async () => {
        setImportPhase('fetchingPoc', {
          message: 'Downloading GitHub PoC feed',
          completed: 0,
          total: 0
        })
        markTaskProgress('poc', 0, 0, 'Downloading GitHub PoC feed')
        return ofetch<unknown>(SOURCE_URL)
      },
      {
        ttlMs,
        forceRefresh: options.forceRefresh,
        allowStale: options.allowStale
      }
    )

    const cacheMessage = dataset.cacheHit
      ? 'Using cached GitHub PoC feed'
      : 'Downloaded GitHub PoC feed'
    markTaskProgress('poc', 0, 0, cacheMessage)

    let payload: unknown = dataset.data

    if (typeof payload === 'string') {
      try {
        payload = JSON.parse(payload)
      } catch (error) {
        throw new Error(
          `GitHub PoC feed cache is corrupted and could not be parsed as JSON: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        )
      }
    }

    const parsed = pocDatasetSchema.safeParse(payload)
    if (!parsed.success) {
      throw new Error('GitHub PoC feed has an invalid format')
    }

    const datasetTimestamp = dataset.cachedAt?.toISOString() ?? ''
    const baseEntries = parsed.data
      .map(entry => toBaseEntry(entry, datasetTimestamp))
      .filter((entry): entry is KevBaseEntry => entry !== null)

    markTaskProgress(
      'poc',
      0,
      0,
      `Filtered GitHub PoC feed to ${baseEntries.length.toLocaleString('en-US')} CVEs with actionable links`
    )

    const totalEnrichment = baseEntries.length

    setImportPhase('enriching', {
      message: 'Enriching GitHub PoC entries with CVE data',
      completed: 0,
      total: totalEnrichment
    })

    markTaskProgress(
      'poc',
      0,
      totalEnrichment,
      'Enriching GitHub PoC entries with CVE data'
    )

    const enrichmentResults = await mapWithConcurrency(
      baseEntries,
      POC_ENRICHMENT_CONCURRENCY,
      async base => {
        try {
          return await enrichBaseEntryWithCvelist(base, {
            preferCache: dataset.cacheHit
          })
        } catch {
          return { entry: base, impacts: [], hit: false }
        }
      },
      {
        onProgress(completed, total) {
          if (total === 0) {
            return
          }
          updateImportProgress('enriching', completed, total)
          markTaskProgress('poc', completed, total)
        }
      }
    )

    const impactRecordMap = new Map<string, VulnerabilityImpactRecord[]>()
    let cvelistHits = 0
    let cvelistMisses = 0

    for (const result of enrichmentResults) {
      if (result.hit) {
        cvelistHits += 1
      } else {
        cvelistMisses += 1
      }

      if (result.impacts.length) {
        impactRecordMap.set(result.entry.id, result.impacts)
      }
    }

    if (cvelistHits > 0 || cvelistMisses > 0) {
      const message = `GitHub PoC CVEList enrichment (${cvelistHits} hits, ${cvelistMisses} misses)`
      markTaskProgress('poc', 0, 0, message)
    }

    const enrichedEntries = enrichmentResults.map(result => enrichEntry(result.entry))

    const historyCandidates = new Map<string, { cveId: string; referenceDate: string | null }>()
    for (const entry of enrichedEntries) {
      if (!historyCandidates.has(entry.cveId)) {
        historyCandidates.set(entry.cveId, {
          cveId: entry.cveId,
          referenceDate: resolveDateAdded(entry, datasetTimestamp)
        })
      }
    }

    const publishDates = await resolvePocPublishDates(
      Array.from(historyCandidates.values()),
      {
        useCachedRepository: options.allowStale ?? dataset.cacheHit,
        lookbackDays: POC_HISTORY_LOOKBACK_DAYS
      }
    )

    await flushCvelistCache()

    const entries = enrichedEntries.map(entry => {
      const pocPublishedAt = publishDates.get(entry.cveId) ?? entry.pocPublishedAt ?? null
      const withPublish = {
        ...entry,
        pocPublishedAt
      }
      const resolvedDate = resolveDateAdded(withPublish, datasetTimestamp)
      return {
        ...withPublish,
        dateAdded: resolvedDate
      }
    })

    const entryRecords = buildEntryDiffRecords(entries, 'poc', impactRecordMap)
    const totalEntries = entryRecords.length
    const useIncremental = strategy === 'incremental'

    if (!useIncremental) {
      setImportPhase('savingPoc', {
        message: 'Saving GitHub PoC entries to the local cache',
        completed: 0,
        total: totalEntries
      })
      markTaskProgress(
        'poc',
        0,
        totalEntries,
        'Saving GitHub PoC entries to the local cache'
      )

      db.transaction(tx => {
        tx
          .delete(tables.vulnerabilityEntries)
          .where(eq(tables.vulnerabilityEntries.source, 'poc'))
          .run()

        for (let index = 0; index < entryRecords.length; index += 1) {
          const record = entryRecords[index]

          tx.insert(tables.vulnerabilityEntries).values(record.values).run()

          if (record.impacts.length) {
            tx.insert(tables.vulnerabilityEntryImpacts).values(record.impacts).run()
          }

          if (record.categories.length) {
            tx
              .insert(tables.vulnerabilityEntryCategories)
              .values(record.categories)
              .run()
          }

          if ((index + 1) % 25 === 0 || index + 1 === entryRecords.length) {
            const message = `Saving GitHub PoC entries (${index + 1} of ${entryRecords.length})`
            setImportPhase('savingPoc', {
              message,
              completed: index + 1,
              total: entryRecords.length
            })
            markTaskProgress('poc', index + 1, entryRecords.length, message)
          }
        }
      })

      const importedAt = new Date().toISOString()
      setMetadata('poc.lastImportAt', importedAt)
      setMetadata('poc.totalCount', String(totalEntries))
      setMetadata('poc.lastNewCount', String(totalEntries))
      setMetadata('poc.lastUpdatedCount', '0')
      setMetadata('poc.lastSkippedCount', '0')
      setMetadata('poc.lastRemovedCount', '0')
      setMetadata('poc.lastImportStrategy', 'full')
      if (datasetTimestamp) {
        setMetadata('poc.cachedAt', datasetTimestamp)
      }

      const summaryLabel = totalEntries
        ? `${totalEntries.toLocaleString()} GitHub PoC entries cached`
        : 'No GitHub PoC entries found'
      markTaskComplete('poc', summaryLabel)

      return {
        imported: totalEntries,
        totalCount: totalEntries,
        newCount: totalEntries,
        updatedCount: 0,
        skippedCount: 0,
        removedCount: 0,
        strategy: 'full',
        cachedAt: datasetTimestamp || null
      }
    }

    const existingMap = loadExistingEntryRecords(db, 'poc')
    const { newRecords, updatedRecords, unchangedRecords, removedIds } =
      diffEntryRecords(entryRecords, existingMap)
    const totalChanges = newRecords.length + updatedRecords.length

    db.transaction(tx => {
      if (totalChanges > 0) {
        const message = 'Saving GitHub PoC changes to the local cache'
        setImportPhase('savingPoc', {
          message,
          completed: 0,
          total: totalChanges
        })
        markTaskProgress('poc', 0, totalChanges, message)
      } else if (removedIds.length > 0) {
        const message = `Removing ${removedIds.length.toLocaleString()} retired GitHub PoC entr${removedIds.length === 1 ? 'y' : 'ies'}`
        setImportPhase('savingPoc', {
          message,
          completed: 0,
          total: 0
        })
        markTaskProgress('poc', 0, 0, message)
      } else {
        const message = 'GitHub PoC catalog already up to date'
        setImportPhase('savingPoc', {
          message,
          completed: 0,
          total: 0
        })
        markTaskProgress('poc', 0, 0, message)
      }

      const persist = (
        record: typeof newRecords[number],
        action: 'insert' | 'update',
        index: number
      ) => {
        persistEntryRecord(tx, record, action)

        if (totalChanges > 0) {
          const completed = index + 1
          const progressMessage = `Saving GitHub PoC changes (${completed} of ${totalChanges})`
          setImportPhase('savingPoc', {
            message: progressMessage,
            completed,
            total: totalChanges
          })
          markTaskProgress('poc', completed, totalChanges, progressMessage)
        }
      }

      let processed = 0
      for (const record of newRecords) {
        persist(record, 'insert', processed)
        processed += 1
      }
      for (const record of updatedRecords) {
        persist(record, 'update', processed)
        processed += 1
      }

      if (removedIds.length > 0) {
        tx
          .delete(tables.vulnerabilityEntries)
          .where(inArray(tables.vulnerabilityEntries.id, removedIds))
          .run()
      }
    })

    const importedAt = new Date().toISOString()
    setMetadata('poc.lastImportAt', importedAt)
    setMetadata('poc.totalCount', String(totalEntries))
    setMetadata('poc.lastNewCount', String(newRecords.length))
    setMetadata('poc.lastUpdatedCount', String(updatedRecords.length))
    setMetadata('poc.lastSkippedCount', String(unchangedRecords.length))
    setMetadata('poc.lastRemovedCount', String(removedIds.length))
    setMetadata('poc.lastImportStrategy', 'incremental')
    if (datasetTimestamp) {
      setMetadata('poc.cachedAt', datasetTimestamp)
    }

    const changeSegments: string[] = []
    if (newRecords.length > 0) {
      changeSegments.push(`${newRecords.length.toLocaleString()} new`)
    }
    if (updatedRecords.length > 0) {
      changeSegments.push(`${updatedRecords.length.toLocaleString()} updated`)
    }
    if (removedIds.length > 0) {
      changeSegments.push(`${removedIds.length.toLocaleString()} removed`)
    }

    const summaryLabel = changeSegments.length
      ? `GitHub PoC catalog updated (${changeSegments.join(', ')})`
      : 'GitHub PoC catalog already up to date'
    markTaskComplete('poc', summaryLabel)

    return {
      imported: totalChanges,
      totalCount: totalEntries,
      newCount: newRecords.length,
      updatedCount: updatedRecords.length,
      skippedCount: unchangedRecords.length,
      removedCount: removedIds.length,
      strategy: 'incremental',
      cachedAt: datasetTimestamp || null
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'GitHub PoC import failed'
    markTaskError('poc', message)
    throw error instanceof Error ? error : new Error(message)
  }
}
