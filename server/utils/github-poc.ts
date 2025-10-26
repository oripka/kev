import { eq } from 'drizzle-orm'
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
  type VulnerabilityImpactRecord
} from './cvelist'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'

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

const toJson = (value: unknown): string => JSON.stringify(value ?? [])

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

  const description = item.desc?.trim() ?? ''
  const primaryPocUrl = pocLinks[0] ?? null
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

  const references = Array.from(new Set([...pocLinks, SOURCE_REPO_URL]))

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
    datePublished: datasetTimestamp || null,
    dateUpdated: datasetTimestamp || null,
    exploitedSince: null,
    sourceUrl: primaryPocUrl ?? SOURCE_REPO_URL,
    pocUrl: primaryPocUrl,
    references,
    aliases: [cveId],
    metasploitModulePath: null,
    metasploitModulePublishedAt: null,
    internetExposed: false
  }
}

type ImportOptions = {
  ttlMs?: number
  forceRefresh?: boolean
  allowStale?: boolean
}

type ImportSummary = {
  imported: number
  cachedAt: string | null
}

export const importGithubPocCatalog = async (
  db: DrizzleDatabase,
  options: ImportOptions = {}
): Promise<ImportSummary> => {
  const ttlMs = options.ttlMs ?? 86_400_000

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

    setImportPhase('enriching', {
      message: 'Enriching GitHub PoC entries with CVE data',
      completed: 0,
      total: baseEntries.length
    })

    markTaskProgress(
      'poc',
      0,
      baseEntries.length,
      'Enriching GitHub PoC entries with CVE data'
    )

    const enrichmentResults = await mapWithConcurrency(
      baseEntries,
      CVELIST_ENRICHMENT_CONCURRENCY,
      async base => {
        try {
          return await enrichBaseEntryWithCvelist(base)
        } catch {
          return { entry: base, impacts: [], hit: false }
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

    const entries = enrichmentResults.map(result => enrichEntry(result.entry))

    setImportPhase('savingPoc', {
      message: 'Saving GitHub PoC entries to the local cache',
      completed: 0,
      total: entries.length
    })
    markTaskProgress('poc', 0, entries.length, 'Saving GitHub PoC entries to the local cache')

    db.transaction(tx => {
      tx
        .delete(tables.vulnerabilityEntries)
        .where(eq(tables.vulnerabilityEntries.source, 'poc'))
        .run()

      for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index]

        tx
          .insert(tables.vulnerabilityEntries)
          .values({
            id: entry.id,
            cveId: entry.cveId,
            source: 'poc',
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
            epssScore: entry.epssScore,
            assigner: entry.assigner,
            datePublished: entry.datePublished,
            dateUpdated: entry.dateUpdated,
            exploitedSince: entry.exploitedSince,
            sourceUrl: entry.sourceUrl,
            pocUrl: entry.pocUrl,
            referenceLinks: toJson(entry.references),
            aliases: toJson(entry.aliases),
            affectedProducts: toJson(entry.affectedProducts),
            problemTypes: toJson(entry.problemTypes),
            metasploitModulePath: entry.metasploitModulePath,
            metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
            internetExposed: entry.internetExposed ? 1 : 0
          })
          .run()

        const impacts = impactRecordMap.get(entry.id) ?? []
        if (impacts.length) {
          for (const impact of impacts) {
            tx
              .insert(tables.vulnerabilityEntryImpacts)
              .values({
                entryId: impact.entryId,
                vendor: impact.vendor,
                vendorKey: impact.vendorKey,
                product: impact.product,
                productKey: impact.productKey,
                status: impact.status,
                versionRange: impact.versionRange,
                source: impact.source
              })
              .run()
          }
        }

        const dimensionRecords: Array<{
          entryId: string
          categoryType: string
          value: string
          name: string
        }> = []

        const pushCategories = (values: string[], type: 'domain' | 'exploit' | 'vulnerability') => {
          for (const value of values) {
            dimensionRecords.push({ entryId: entry.id, categoryType: type, value, name: value })
          }
        }

        pushCategories(entry.domainCategories, 'domain')
        pushCategories(entry.exploitLayers, 'exploit')
        pushCategories(entry.vulnerabilityCategories, 'vulnerability')

        if (dimensionRecords.length) {
          tx.insert(tables.vulnerabilityEntryCategories).values(dimensionRecords).run()
        }

        if ((index + 1) % 25 === 0 || index + 1 === entries.length) {
          const message = `Saving GitHub PoC entries (${index + 1} of ${entries.length})`
          setImportPhase('savingPoc', {
            message,
            completed: index + 1,
            total: entries.length
          })
          markTaskProgress('poc', index + 1, entries.length, message)
        }
      }
    })

    const importedAt = new Date().toISOString()
    setMetadata('poc.lastImportAt', importedAt)
    setMetadata('poc.totalCount', String(entries.length))
    if (datasetTimestamp) {
      setMetadata('poc.cachedAt', datasetTimestamp)
    }

    const summaryLabel = entries.length
      ? `${entries.length.toLocaleString()} GitHub PoC entries cached`
      : 'No GitHub PoC entries found'
    markTaskComplete('poc', summaryLabel)

    return { imported: entries.length, cachedAt: datasetTimestamp || null }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'GitHub PoC import failed'
    markTaskError('poc', message)
    throw error instanceof Error ? error : new Error(message)
  }
}
