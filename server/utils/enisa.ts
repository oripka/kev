import { eq } from 'drizzle-orm'
import { ofetch } from 'ofetch'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import type { KevEntry } from '~/types'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { getCachedData } from './cache'
import { setMetadata } from './sqlite'
import {
  CVELIST_ENRICHMENT_CONCURRENCY,
  enrichBaseEntryWithCvelist,
  type VulnerabilityImpactRecord
} from './cvelist'
import { mapWithConcurrency } from './concurrency'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'

type EnisaApiProduct = {
  product?: {
    name?: string | null
  } | null
  product_version?: string | null
}

type EnisaApiVendor = {
  vendor?: {
    name?: string | null
  } | null
}

type EnisaApiItem = {
  id: string
  enisaUuid?: string | null
  description?: string | null
  datePublished?: string | null
  dateUpdated?: string | null
  baseScore?: number | string | null
  baseScoreVersion?: string | null
  baseScoreVector?: string | null
  references?: string | null
  aliases?: string | null
  assigner?: string | null
  epss?: number | string | null
  exploitedSince?: string | null
  enisaIdProduct?: EnisaApiProduct[] | null
  enisaIdVendor?: EnisaApiVendor[] | null
}

type EnisaApiResponse = {
  items: EnisaApiItem[]
  total: number
}

const ENISA_ENDPOINT = 'https://euvdservices.enisa.europa.eu/api/search'
const PAGE_SIZE = 100

const splitLines = (value?: string | null): string[] =>
  (value ?? '')
    .split('\n')
    .map(entry => entry.trim())
    .filter(Boolean)

const extractCveId = (aliases: string[]): string | null => {
  for (const alias of aliases) {
    const match = alias.match(/CVE-\d{4}-\d+/i)
    if (match) {
      return match[0].toUpperCase()
    }
  }
  return null
}

const parseDate = (value?: string | null): string | null => {
  if (!value) {
    return null
  }

  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return null
  }

  return parsed.toISOString()
}

const normaliseNumber = (value: unknown): number | null => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number.parseFloat(value.trim())
    return Number.isNaN(parsed) ? null : parsed
  }
  return null
}

const toCvssSeverity = (score: number | null): KevEntry['cvssSeverity'] => {
  if (typeof score !== 'number' || Number.isNaN(score)) {
    return null
  }

  if (score <= 0) {
    return 'None'
  }
  if (score < 4) {
    return 'Low'
  }
  if (score < 7) {
    return 'Medium'
  }
  if (score < 9) {
    return 'High'
  }
  return 'Critical'
}

const toProductLabel = (product: EnisaApiProduct | undefined): string => {
  const name = product?.product?.name?.trim()
  const version = product?.product_version?.trim()

  if (name && version) {
    return `${name} ${version}`
  }

  if (name) {
    return name
  }

  return 'Unknown'
}

const toVendorLabel = (vendor: EnisaApiVendor | undefined): string => {
  return vendor?.vendor?.name?.trim() || 'Unknown'
}

const toBaseEntry = (item: EnisaApiItem): KevBaseEntry | null => {
  const aliases = splitLines(item.aliases)
  const cveId = extractCveId(aliases)
  if (!cveId) {
    return null
  }

  const vendor = toVendorLabel(item.enisaIdVendor?.[0])
  const product = toProductLabel(item.enisaIdProduct?.[0])
  const normalised = normaliseVendorProduct({ vendor, product })

  const exploitedSince = parseDate(item.exploitedSince)
  const datePublished = parseDate(item.datePublished)
  const dateUpdated = parseDate(item.dateUpdated)

  const cvssScore = normaliseNumber(item.baseScore)
  const epssScore = normaliseNumber(item.epss)

  const references = splitLines(item.references)
  const sourceUrl = references[0] ?? null

  const dateAdded = exploitedSince ?? datePublished ?? ''

  const uniqueId = item.id?.trim() || item.enisaUuid?.trim() || cveId
  if (!uniqueId) {
    return null
  }

  const baseEntry: KevBaseEntry = {
    id: `enisa:${uniqueId}`,
    sources: ['enisa'],
    cveId,
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    affectedProducts: [],
    problemTypes: [],
    vulnerabilityName: aliases[0] ?? item.id,
    description: item.description?.trim() ?? '',
    requiredAction: null,
    dateAdded,
    dueDate: null,
    ransomwareUse: null,
    notes: [],
    cwes: [],
    cvssScore,
    cvssVector: item.baseScoreVector ?? null,
    cvssVersion: item.baseScoreVersion ?? null,
    cvssSeverity: toCvssSeverity(cvssScore),
    epssScore,
    assigner: item.assigner?.trim() ?? null,
    datePublished,
    dateUpdated,
    exploitedSince,
    sourceUrl,
    references,
    aliases,
    metasploitModulePath: null,
    metasploitModulePublishedAt: null,
    internetExposed: false
  }

  return baseEntry
}

const toJson = (value: unknown[] | undefined): string => JSON.stringify(value ?? [])

const fetchPage = async (page: number, size: number): Promise<EnisaApiResponse> => {
  return ofetch<EnisaApiResponse>(ENISA_ENDPOINT, {
    query: {
      exploited: 'true',
      fromScore: '0',
      toScore: '10',
      page: String(page),
      size: String(size)
    }
  })
}

type EnisaCacheBundle = {
  total: number
  items: EnisaApiItem[]
}

type ImportOptions = {
  ttlMs?: number
  forceRefresh?: boolean
  allowStale?: boolean
}

export const importEnisaCatalog = async (
  db: DrizzleDatabase,
  options: ImportOptions = {}
): Promise<{ imported: number; lastUpdated: string | null }> => {
  const { ttlMs = 86_400_000, forceRefresh = false, allowStale = false } = options

  markTaskRunning('enisa', 'Checking ENISA cache')

  try {
    setImportPhase('fetchingEnisa', {
      message: 'Checking ENISA cache',
      completed: 0,
      total: 0
    })
    markTaskProgress('enisa', 0, 0, 'Checking ENISA cache')

    const dataset = await getCachedData<EnisaCacheBundle>(
      'enisa-feed',
      async () => {
        setImportPhase('fetchingEnisa', {
          message: 'Fetching exploited ENISA vulnerabilities',
          completed: 0,
          total: 0
        })
        markTaskProgress('enisa', 0, 0, 'Fetching exploited ENISA vulnerabilities')

        let page = 0
        const items: EnisaApiItem[] = []
        let total = 0

        // Fetch paginated results
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const response = await fetchPage(page, PAGE_SIZE)

          if (page === 0) {
            total = response.total
          }

          items.push(...response.items)

          const completed = Math.min(items.length, total)
          const message = `Fetching exploited ENISA vulnerabilities (${completed} of ${total})`
          setImportPhase('fetchingEnisa', {
            message,
            completed,
            total
          })
          markTaskProgress('enisa', completed, total, message)

          if (items.length >= total || response.items.length === 0) {
            break
          }

          page += 1
        }

        return { total, items }
      },
      { ttlMs, forceRefresh, allowStale }
    )

    const entryById = new Map<string, KevBaseEntry>()

    for (const item of dataset.data.items) {
      const baseEntry = toBaseEntry(item)
      if (!baseEntry || entryById.has(baseEntry.id)) {
        continue
      }
      entryById.set(baseEntry.id, baseEntry)
    }

    const baseEntries = Array.from(entryById.values())

    setImportPhase('enriching', {
      message: 'Enriching ENISA entries with classification data'
    })

    const cvelistResults = await mapWithConcurrency(
      baseEntries,
      CVELIST_ENRICHMENT_CONCURRENCY,
      async base => {
        try {
          return await enrichBaseEntryWithCvelist(base, {
            preferCache: allowStale
          })
        } catch {
          return { entry: base, impacts: [], hit: false }
        }
      }
    )

    let cvelistHits = 0
    let cvelistMisses = 0
    for (const result of cvelistResults) {
      if (result.hit) {
        cvelistHits += 1
      } else {
        cvelistMisses += 1
      }
    }

    if (cvelistHits > 0 || cvelistMisses > 0) {
      const message = `ENISA CVEList enrichment (${cvelistHits} hits, ${cvelistMisses} misses)`
      markTaskProgress('enisa', 0, 0, message)
    }

    const impactRecordMap = new Map<string, VulnerabilityImpactRecord[]>()
    for (const result of cvelistResults) {
      if (result.impacts.length) {
        impactRecordMap.set(result.entry.id, result.impacts)
      }
    }

    const entries = cvelistResults.map(result => enrichEntry(result.entry))

    setImportPhase('savingEnisa', {
      message: 'Saving ENISA entries to the local cache',
      completed: 0,
      total: entries.length
    })
    markTaskProgress('enisa', 0, entries.length, 'Saving ENISA entries to the local cache')

    db.transaction(tx => {
      tx
        .delete(tables.vulnerabilityEntries)
        .where(eq(tables.vulnerabilityEntries.source, 'enisa'))
        .run()

      for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index]

        tx
          .insert(tables.vulnerabilityEntries)
          .values({
            id: entry.id,
            cveId: entry.cveId,
            source: 'enisa',
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
            referenceLinks: toJson(entry.references),
            aliases: toJson(entry.aliases),
            affectedProducts: toJson(entry.affectedProducts),
            problemTypes: toJson(entry.problemTypes),
            metasploitModulePath: entry.metasploitModulePath,
            metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
            internetExposed: entry.internetExposed ? 1 : 0
          })
          .run()

        const entryImpacts = impactRecordMap.get(entry.id) ?? []
        if (entryImpacts.length) {
          for (const impact of entryImpacts) {
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

        if ((index + 1) % 25 === 0 || index + 1 === entries.length) {
          const message = `Saving ENISA entries to the local cache (${index + 1} of ${entries.length})`
          setImportPhase('savingEnisa', {
            message,
            completed: index + 1,
            total: entries.length
          })
          markTaskProgress('enisa', index + 1, entries.length, message)
        }
      }
    })

    const importedAt = new Date().toISOString()
    setMetadata('enisa.lastImportAt', importedAt)
    setMetadata('enisa.totalCount', String(entries.length))

    const latestUpdatedAt = entries
      .map(entry => entry.dateUpdated ?? entry.exploitedSince ?? entry.datePublished)
      .filter((value): value is string => typeof value === 'string')
      .sort()
      .at(-1) ?? null

    if (latestUpdatedAt) {
      setMetadata('enisa.lastUpdatedAt', latestUpdatedAt)
    }

    markTaskComplete('enisa', `${entries.length.toLocaleString()} ENISA entries cached`)

    return {
      imported: entries.length,
      lastUpdated: latestUpdatedAt
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : typeof error === 'string' ? error : 'ENISA import failed'
    markTaskError('enisa', message)
    throw error instanceof Error ? error : new Error(message)
  }
}
