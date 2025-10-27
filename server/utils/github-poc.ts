import { ofetch } from 'ofetch'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
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
  createEntryRecords,
  saveEntryRecords,
  type ImportStrategy
} from './importDiff'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase,
  updateImportProgress
} from './import-progress'
import { resolvePocPublishDates } from './github-poc-history'

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

type ImportSummary = {
  imported: number
  total: number
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
): Promise<ImportSummary> => {
  const ttlMs = options.ttlMs ?? 86_400_000
  const strategy: ImportStrategy = options.strategy === 'incremental' ? 'incremental' : 'full'

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
    const entryRecords = createEntryRecords(entries, 'poc', impactRecordMap)

    const saveResult = saveEntryRecords({
      db,
      source: 'poc',
      records: entryRecords,
      strategy,
      callbacks: {
        onFullStart(total) {
          setImportPhase('savingPoc', {
            message: 'Saving GitHub PoC entries to the local cache',
            completed: 0,
            total
          })
          markTaskProgress('poc', 0, total, 'Saving GitHub PoC entries to the local cache')
        },
        onFullProgress(index, total) {
          if ((index + 1) % 25 !== 0 && index + 1 !== total) {
            return
          }
          const completed = index + 1
          const message = `Saving GitHub PoC entries (${completed} of ${total})`
          setImportPhase('savingPoc', { message, completed, total })
          markTaskProgress('poc', completed, total, message)
        },
        onIncrementalStart({ totalChanges, removedCount }) {
          if (totalChanges > 0) {
            const message = 'Saving GitHub PoC changes to the local cache'
            setImportPhase('savingPoc', { message, completed: 0, total: totalChanges })
            markTaskProgress('poc', 0, totalChanges, message)
          } else if (removedCount > 0) {
            const message = `Removing ${removedCount.toLocaleString()} retired PoC entr${removedCount === 1 ? 'y' : 'ies'}`
            setImportPhase('savingPoc', { message, completed: 0, total: 0 })
            markTaskProgress('poc', 0, 0, message)
          } else {
            const message = 'GitHub PoC catalog already up to date'
            setImportPhase('savingPoc', { message, completed: 0, total: 0 })
            markTaskProgress('poc', 0, 0, message)
          }
        },
        onIncrementalProgress(processed, totalChanges) {
          const message = `Saving GitHub PoC changes (${processed} of ${totalChanges})`
          setImportPhase('savingPoc', { message, completed: processed, total: totalChanges })
          markTaskProgress('poc', processed, totalChanges, message)
        }
      }
    })

    const importedAt = new Date().toISOString()
    setMetadata('poc.lastImportAt', importedAt)
    setMetadata('poc.totalCount', String(entries.length))
    setMetadata('poc.lastNewCount', String(saveResult.newCount))
    setMetadata('poc.lastUpdatedCount', String(saveResult.updatedCount))
    setMetadata('poc.lastSkippedCount', String(saveResult.skippedCount))
    setMetadata('poc.lastRemovedCount', String(saveResult.removedCount))
    setMetadata('poc.lastImportStrategy', strategy)
    if (datasetTimestamp) {
      setMetadata('poc.cachedAt', datasetTimestamp)
    }

    const detailSegments: string[] = []
    if (saveResult.newCount > 0) {
      detailSegments.push(`${saveResult.newCount.toLocaleString()} new`)
    }
    if (saveResult.updatedCount > 0) {
      detailSegments.push(`${saveResult.updatedCount.toLocaleString()} updated`)
    }
    if (saveResult.skippedCount > 0) {
      detailSegments.push(`${saveResult.skippedCount.toLocaleString()} unchanged`)
    }
    if (saveResult.removedCount > 0) {
      detailSegments.push(`${saveResult.removedCount.toLocaleString()} removed`)
    }

    if (strategy === 'incremental') {
      const detailSummary = detailSegments.length
        ? detailSegments.join(', ')
        : 'no changes detected'
      markTaskComplete('poc', `Incremental GitHub PoC import: ${detailSummary}`)
    } else {
      const summaryLabel = entries.length
        ? `${entries.length.toLocaleString()} GitHub PoC entries cached`
        : 'No GitHub PoC entries found'
      markTaskComplete('poc', summaryLabel)
    }

    return {
      imported: saveResult.newCount + saveResult.updatedCount,
      total: entries.length,
      newCount: saveResult.newCount,
      updatedCount: saveResult.updatedCount,
      skippedCount: saveResult.skippedCount,
      removedCount: saveResult.removedCount,
      strategy,
      cachedAt: datasetTimestamp || null
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'GitHub PoC import failed'
    markTaskError('poc', message)
    throw error instanceof Error ? error : new Error(message)
  }
}
