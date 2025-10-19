import { ofetch } from 'ofetch'
import type { Database as SqliteDatabase } from 'better-sqlite3'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry, KevEntry } from '~/types'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { getCachedData } from './cache'
import { setMetadata } from './sqlite'
import { setImportPhase } from './import-progress'

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
  db: SqliteDatabase,
  options: ImportOptions = {}
): Promise<{ imported: number; lastUpdated: string | null }> => {
  const { ttlMs = 86_400_000, forceRefresh = false, allowStale = false } = options

  setImportPhase('fetchingEnisa', {
    message: 'Checking ENISA cache',
    completed: 0,
    total: 0
  })

  const dataset = await getCachedData<EnisaCacheBundle>(
    'enisa-feed',
    async () => {
      setImportPhase('fetchingEnisa', {
        message: 'Fetching exploited ENISA vulnerabilities',
        completed: 0,
        total: 0
      })

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

        setImportPhase('fetchingEnisa', {
          message: `Fetching exploited ENISA vulnerabilities (${Math.min(items.length, total)} of ${total})`,
          completed: Math.min(items.length, total),
          total
        })

        if (items.length >= total || response.items.length === 0) {
          break
        }

        page += 1
      }

      return { total, items }
    },
    { ttlMs, forceRefresh, allowStale }
  )

  if (dataset.cacheHit) {
    const cachedCount = dataset.data.items.length
    setImportPhase('fetchingEnisa', {
      message: `Using cached ENISA vulnerabilities (${cachedCount})`,
      completed: cachedCount,
      total: cachedCount
    })
  }

  const { items } = dataset.data

  const entryById = new Map<string, KevBaseEntry>()

  for (const item of items) {
    const baseEntry = toBaseEntry(item)
    if (!baseEntry) {
      continue
    }

    if (entryById.has(baseEntry.id)) {
      continue
    }

    entryById.set(baseEntry.id, baseEntry)
  }

  const baseEntries = Array.from(entryById.values())

  setImportPhase('enriching', {
    message: 'Enriching ENISA entries with classification data'
  })

  const entries = baseEntries.map(enrichEntry)

  setImportPhase('savingEnisa', {
    message: 'Saving ENISA entries to the local cache',
    completed: 0,
    total: entries.length
  })

  const deleteEntries = db.prepare(`DELETE FROM vulnerability_entries WHERE source = 'enisa'`)
  const insertEntry = db.prepare(
    `INSERT INTO vulnerability_entries (
      id,
      cve_id,
      source,
      vendor,
      product,
      vulnerability_name,
      description,
      required_action,
      date_added,
      due_date,
      ransomware_use,
      notes,
      cwes,
      cvss_score,
      cvss_vector,
      cvss_version,
      cvss_severity,
      epss_score,
      assigner,
      date_published,
      date_updated,
      exploited_since,
      source_url,
      reference_links,
      aliases,
      internet_exposed
    ) VALUES (
      @id,
      @cve_id,
      @source,
      @vendor,
      @product,
      @vulnerability_name,
      @description,
      @required_action,
      @date_added,
      @due_date,
      @ransomware_use,
      @notes,
      @cwes,
      @cvss_score,
      @cvss_vector,
      @cvss_version,
      @cvss_severity,
      @epss_score,
      @assigner,
      @date_published,
      @date_updated,
      @exploited_since,
      @source_url,
      @reference_links,
      @aliases,
      @internet_exposed
    )`
  )
  const insertCategory = db.prepare(
    `INSERT INTO vulnerability_entry_categories (
      entry_id,
      category_type,
      value,
      name
    ) VALUES (
      @entry_id,
      @category_type,
      @value,
      @name
    )`
  )

  const transaction = db.transaction((itemsToSave: KevEntry[]) => {
    deleteEntries.run()

    const pushCategories = (
      entryId: string,
      values: string[],
      type: 'domain' | 'exploit' | 'vulnerability'
    ) => {
      for (const value of values) {
        insertCategory.run({
          entry_id: entryId,
          category_type: type,
          value,
          name: value
        })
      }
    }

    for (let index = 0; index < itemsToSave.length; index += 1) {
      const entry = itemsToSave[index]
      insertEntry.run({
        id: entry.id,
        cve_id: entry.cveId,
        source: 'enisa',
        vendor: entry.vendor,
        product: entry.product,
        vulnerability_name: entry.vulnerabilityName,
        description: entry.description,
        required_action: entry.requiredAction,
        date_added: entry.dateAdded,
        due_date: entry.dueDate,
        ransomware_use: entry.ransomwareUse,
        notes: toJson(entry.notes),
        cwes: toJson(entry.cwes),
        cvss_score: entry.cvssScore,
        cvss_vector: entry.cvssVector,
        cvss_version: entry.cvssVersion,
        cvss_severity: entry.cvssSeverity,
        epss_score: entry.epssScore,
        assigner: entry.assigner,
        date_published: entry.datePublished,
        date_updated: entry.dateUpdated,
        exploited_since: entry.exploitedSince,
        source_url: entry.sourceUrl,
        reference_links: toJson(entry.references),
        aliases: toJson(entry.aliases),
        internet_exposed: entry.internetExposed ? 1 : 0
      })

      pushCategories(entry.id, entry.domainCategories, 'domain')
      pushCategories(entry.id, entry.exploitLayers, 'exploit')
      pushCategories(entry.id, entry.vulnerabilityCategories, 'vulnerability')

      if ((index + 1) % 25 === 0 || index + 1 === itemsToSave.length) {
        setImportPhase('savingEnisa', {
          message: `Saving ENISA entries (${index + 1} of ${itemsToSave.length})`,
          completed: index + 1,
          total: itemsToSave.length
        })
      }
    }
  })

  transaction(entries)

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

  return {
    imported: entries.length,
    lastUpdated: latestUpdatedAt
  }
}
