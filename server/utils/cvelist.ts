import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { syncSparseRepo, ensureDir } from './git'
import { setMetadata } from './sqlite'
import {
  CVELIST_REPO_DIR,
  readCveRecord,
  summariseCveRecord,
  type CvelistRecordSummary,
  type NormalisedVersion
} from './cvelist-parser'
import type { KevBaseEntry } from '~/utils/classification'
import type {
  KevAffectedProduct,
  KevProblemType,
  KevVersionRange
} from '~/types'

const CVELIST_CACHE_DIR = join(process.cwd(), 'data', 'cache', 'cvelist')
const CVELIST_INDEX_PATH = join(CVELIST_CACHE_DIR, 'cvelist-index.json')
const CVELIST_REPO_URL = 'https://github.com/CVEProject/cvelistV5.git'
const CVELIST_BRANCH = 'main'

type PersistedCache = {
  commit: string | null
  records: Record<string, CvelistRecordSummary & { cachedAt: string }>
}

const inMemoryCache = new Map<string, CvelistRecordSummary>()
let persistedCache: PersistedCache | null = null
let cacheLoaded = false

const loadPersistedCache = async () => {
  if (cacheLoaded) {
    return persistedCache
  }
  cacheLoaded = true
  try {
    const contents = await readFile(CVELIST_INDEX_PATH, 'utf8')
    const parsed = JSON.parse(contents) as PersistedCache
    if (!parsed.records || typeof parsed.records !== 'object') {
      persistedCache = { commit: null, records: {} }
      return persistedCache
    }
    persistedCache = parsed
  } catch {
    persistedCache = { commit: null, records: {} }
  }
  return persistedCache
}

const persistCache = async () => {
  if (!persistedCache) {
    return
  }
  await ensureDir(CVELIST_CACHE_DIR)
  const serialised = JSON.stringify(persistedCache, null, 2)
  await writeFile(CVELIST_INDEX_PATH, serialised, 'utf8')
}

const normaliseVersionRange = (version: NormalisedVersion): KevVersionRange => ({
  version: version.version ?? null,
  introduced: version.introduced ?? null,
  fixed: version.fixed ?? null,
  lessThan: version.lessThan ?? null,
  lessThanOrEqual: version.lessThanOrEqual ?? null,
  greaterThan: version.greaterThan ?? null,
  greaterThanOrEqual: version.greaterThanOrEqual ?? null,
  status: version.status ?? null,
  versionType: version.versionType ?? null
})

const toAffectedProducts = (summary: CvelistRecordSummary): KevAffectedProduct[] => {
  const products: KevAffectedProduct[] = []
  for (const vendor of summary.vendors) {
    for (const product of vendor.products) {
      const rangeList = product.versions.map(version => normaliseVersionRange(version))
      products.push({
        vendor: vendor.vendor,
        vendorKey: vendor.vendorKey,
        product: product.product,
        productKey: product.productKey,
        status: product.status ?? '',
        source: product.source,
        platforms: [...product.platforms],
        versions: rangeList
      })
    }
  }
  return products
}

const toProblemTypes = (summary: CvelistRecordSummary): KevProblemType[] => {
  return summary.cwes.map(entry => ({
    cweId: entry.cweId,
    description: entry.description,
    source: entry.source
  }))
}

type SelectPrimaryOptions = {
  preferredVendorKey?: string | null
  preferredProductKey?: string | null
}

const selectPrimaryProduct = (
  products: KevAffectedProduct[],
  options: SelectPrimaryOptions
): KevAffectedProduct | null => {
  if (!products.length) {
    return null
  }

  const { preferredVendorKey, preferredProductKey } = options

  if (preferredVendorKey || preferredProductKey) {
    const matched = products.find(product => {
      const vendorMatches = preferredVendorKey
        ? product.vendorKey === preferredVendorKey
        : true
      const productMatches = preferredProductKey
        ? product.productKey === preferredProductKey
        : true
      return vendorMatches && productMatches
    })
    if (matched) {
      return matched
    }
  }

  return products[0]
}

export type CvelistEnrichment = {
  primaryProduct: KevAffectedProduct | null
  affectedProducts: KevAffectedProduct[]
  problemTypes: KevProblemType[]
  references: string[]
  descriptions: CvelistRecordSummary['descriptions']
  datePublished?: string
  dateUpdated?: string
  assigner?: string
}

export const buildCvelistEnrichment = (
  summary: CvelistRecordSummary,
  options: SelectPrimaryOptions = {}
): CvelistEnrichment => {
  const affectedProducts = toAffectedProducts(summary)
  const problemTypes = toProblemTypes(summary)
  const primaryProduct = selectPrimaryProduct(affectedProducts, options)

  return {
    primaryProduct,
    affectedProducts,
    problemTypes,
    references: summary.references,
    descriptions: summary.descriptions,
    datePublished: summary.datePublished,
    dateUpdated: summary.dateUpdated,
    assigner: summary.assigner
  }
}

export type VulnerabilityImpactRecord = {
  entryId: string
  vendor: string
  vendorKey: string
  product: string
  productKey: string
  status: string
  versionRange: string
  source: 'cna' | 'adp' | 'cpe'
}

export const buildImpactRecords = (
  entryId: string,
  products: KevAffectedProduct[]
): VulnerabilityImpactRecord[] => {
  const records: VulnerabilityImpactRecord[] = []
  const seen = new Set<string>()

  for (const product of products) {
    if (!product.versions.length) {
      const identifier = `${entryId}:${product.vendorKey}:${product.productKey}:${product.status ?? ''}:empty:${product.source}`
      if (seen.has(identifier)) {
        continue
      }
      seen.add(identifier)
      records.push({
        entryId,
        vendor: product.vendor,
        vendorKey: product.vendorKey,
        product: product.product,
        productKey: product.productKey,
        status: product.status ?? '',
        versionRange: JSON.stringify({}),
        source: product.source
      })
      continue
    }

    for (const version of product.versions) {
      const versionRange = JSON.stringify(version)
      const identifier = `${entryId}:${product.vendorKey}:${product.productKey}:${version.status ?? product.status ?? ''}:${versionRange}:${product.source}`
      if (seen.has(identifier)) {
        continue
      }
      seen.add(identifier)
      records.push({
        entryId,
        vendor: product.vendor,
        vendorKey: product.vendorKey,
        product: product.product,
        productKey: product.productKey,
        status: version.status ?? product.status ?? '',
        versionRange,
        source: product.source
      })
    }
  }

  return records
}

type EnrichBaseEntryOptions = {
  preferCache?: boolean
}

export type EnrichBaseEntryResult = {
  entry: KevBaseEntry
  impacts: VulnerabilityImpactRecord[]
  hit: boolean
}

const cloneStringArray = (values: string[] | undefined): string[] => {
  if (!Array.isArray(values)) {
    return []
  }
  return [...values]
}

const cloneProblemTypes = (values: KevProblemType[] | undefined): KevProblemType[] => {
  if (!Array.isArray(values)) {
    return []
  }
  return values.map(value => ({ ...value }))
}

const cloneAffectedProducts = (values: KevAffectedProduct[] | undefined): KevAffectedProduct[] => {
  if (!Array.isArray(values)) {
    return []
  }
  return values.map(product => ({
    ...product,
    platforms: [...product.platforms],
    versions: product.versions.map(version => ({ ...version }))
  }))
}

export const enrichBaseEntryWithCvelist = async (
  base: KevBaseEntry,
  options: EnrichBaseEntryOptions = {}
): Promise<EnrichBaseEntryResult> => {
  const { preferCache = false } = options

  const workingEntry: KevBaseEntry = {
    ...base,
    notes: cloneStringArray(base.notes),
    references: cloneStringArray(base.references),
    aliases: cloneStringArray(base.aliases),
    cwes: cloneStringArray(base.cwes),
    affectedProducts: cloneAffectedProducts(base.affectedProducts),
    problemTypes: cloneProblemTypes(base.problemTypes)
  }

  try {
    const summary = await loadCvelistRecord(base.cveId, { preferCache })

    if (!summary) {
      return { entry: workingEntry, impacts: [], hit: false }
    }

    const enrichment = buildCvelistEnrichment(summary, {
      preferredVendorKey: base.vendorKey,
      preferredProductKey: base.productKey
    })

    if (enrichment.primaryProduct) {
      if (enrichment.primaryProduct.vendor) {
        workingEntry.vendor = enrichment.primaryProduct.vendor
      }
      if (enrichment.primaryProduct.vendorKey) {
        workingEntry.vendorKey = enrichment.primaryProduct.vendorKey
      }
      if (enrichment.primaryProduct.product) {
        workingEntry.product = enrichment.primaryProduct.product
      }
      if (enrichment.primaryProduct.productKey) {
        workingEntry.productKey = enrichment.primaryProduct.productKey
      }
    }

    workingEntry.affectedProducts = enrichment.affectedProducts
    workingEntry.problemTypes = enrichment.problemTypes

    if (!workingEntry.assigner && enrichment.assigner) {
      workingEntry.assigner = enrichment.assigner
    }

    if (!workingEntry.datePublished && enrichment.datePublished) {
      workingEntry.datePublished = enrichment.datePublished
    }

    if (!workingEntry.dateUpdated && enrichment.dateUpdated) {
      workingEntry.dateUpdated = enrichment.dateUpdated
    }

    if (!workingEntry.description && enrichment.descriptions.length > 0) {
      const preferredDescription =
        enrichment.descriptions.find(description => description.lang.toLowerCase() === 'en') ??
        enrichment.descriptions[0]

      if (preferredDescription?.value) {
        workingEntry.description = preferredDescription.value
      }
    }

    if (!Array.isArray(workingEntry.references)) {
      workingEntry.references = []
    }

    const referenceSet = new Set(
      workingEntry.references.map(reference => reference.toLowerCase())
    )
    for (const reference of enrichment.references) {
      const key = reference.toLowerCase()
      if (referenceSet.has(key)) {
        continue
      }
      referenceSet.add(key)
      workingEntry.references.push(reference)
    }

    if (!workingEntry.cwes.length) {
      const cweIds = enrichment.problemTypes
        .map(problem => problem.cweId)
        .filter((value): value is string => Boolean(value))

      const cweSet = new Set(workingEntry.cwes)
      for (const cweId of cweIds) {
        if (!cweSet.has(cweId)) {
          cweSet.add(cweId)
          workingEntry.cwes.push(cweId)
        }
      }
    }

    const impacts = buildImpactRecords(base.id, enrichment.affectedProducts)
    return { entry: workingEntry, impacts, hit: true }
  } catch {
    // Surface cache hits even when parsing fails, but continue gracefully.
    return { entry: workingEntry, impacts: [], hit: false }
  }
}

export const syncCvelistRepo = async (
  options: { useCachedRepository?: boolean } = {}
): Promise<{ commit: string | null; updated: boolean }> => {
  await ensureDir(CVELIST_CACHE_DIR)
  const result = await syncSparseRepo({
    repoUrl: CVELIST_REPO_URL,
    branch: CVELIST_BRANCH,
    workingDir: CVELIST_REPO_DIR,
    sparsePaths: ['cves'],
    useCachedRepository: options.useCachedRepository
  })

  if (persistedCache && result.commit && persistedCache.commit !== result.commit) {
    persistedCache.commit = result.commit
    await persistCache()
  }

  if (result.commit) {
    setMetadata('cvelist.lastCommit', result.commit)
  }

  return result
}

type LoadOptions = {
  preferCache?: boolean
}

export const loadCvelistRecord = async (
  cveId: string,
  options: LoadOptions = {}
): Promise<CvelistRecordSummary | null> => {
  const { preferCache = false } = options

  if (inMemoryCache.has(cveId)) {
    return inMemoryCache.get(cveId) ?? null
  }

  const cache = await loadPersistedCache()
  const cached = cache?.records?.[cveId]

  if (cached && preferCache) {
    inMemoryCache.set(cveId, cached)
    return cached
  }

  try {
    const record = await readCveRecord(cveId)
    const summary = summariseCveRecord(cveId, record)
    inMemoryCache.set(cveId, summary)

    if (cache) {
      cache.records[cveId] = { ...summary, cachedAt: new Date().toISOString() }
      if (cache.commit === undefined) {
        cache.commit = null
      }
      await persistCache()
    }

    return summary
  } catch (error) {
    return cached ?? null
  }
}

export const clearCvelistMemoryCache = () => {
  inMemoryCache.clear()
}
