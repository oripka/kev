import { getQuery } from 'h3'
import { lookupCveName } from '~/utils/cveToNameMap'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import type {
  CatalogSource,
  KevCountDatum,
  KevDomainCategory,
  KevEntry,
  KevExploitLayer,
  KevResponse,
  KevVulnerabilityCategory
} from '~/types'
import { getDatabase, getMetadata } from '../utils/sqlite'

type KevRow = {
  cve_id: string
  vendor: string | null
  product: string | null
  vulnerability_name: string | null
  description: string | null
  required_action: string | null
  date_added: string | null
  due_date: string | null
  ransomware_use: string | null
  notes: string | null
  cwes: string | null
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  cvss_severity: string | null
  domain_categories: string | null
  exploit_layers: string | null
  vulnerability_categories: string | null
  internet_exposed: number | null
  updated_at: string | null
}

type EnisaRow = {
  enisa_id: string
  cve_id: string | null
  vendor: string | null
  product: string | null
  vulnerability_name: string | null
  description: string | null
  assigner: string | null
  date_published: string | null
  date_updated: string | null
  exploited_since: string | null
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  cvss_severity: string | null
  epss_score: number | null
  reference_links: string | null
  aliases: string | null
  domain_categories: string | null
  exploit_layers: string | null
  vulnerability_categories: string | null
  source_url: string | null
  internet_exposed: number | null
  updated_at: string | null
}

type CatalogQuery = {
  search?: string
  vendor?: string
  vendorKeys?: string[]
  product?: string
  productKeys?: string[]
  ownedOnly?: boolean
  domain?: KevDomainCategory
  exploit?: KevExploitLayer
  vulnerability?: KevVulnerabilityCategory
  startYear?: number
  endYear?: number
  wellKnownOnly?: boolean
  source?: CatalogSource
  cvssMin?: number
  cvssMax?: number
  epssMin?: number
  epssMax?: number
  fromDate?: string
  toDate?: string
  fromUpdatedDate?: string
  toUpdatedDate?: string
  ransomwareOnly?: boolean
  internetExposedOnly?: boolean
}

const DEFAULT_VENDOR = 'Unknown'
const DEFAULT_PRODUCT = 'Unknown'
const DEFAULT_VULNERABILITY = 'Unknown vulnerability'

const parseJsonArray = (value: string | null): string[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed.filter((item): item is string => typeof item === 'string').map(item => item.trim()).filter(Boolean)
  } catch {
    return []
  }
}

const parseAliasArray = (value: string | null): string[] =>
  parseJsonArray(value).map(alias => alias.toUpperCase())

const normaliseCve = (value: string): string => value.toUpperCase()

const ensureString = (value: string | null | undefined, fallback: string): string => {
  const trimmed = value?.trim()
  return trimmed && trimmed.length ? trimmed : fallback
}

const mergeUniqueStrings = (first: string[], second: string[]): string[] => {
  const seen = new Set<string>()
  const result: string[] = []

  for (const value of [...first, ...second]) {
    const trimmed = value?.trim()
    if (!trimmed || seen.has(trimmed)) {
      continue
    }
    seen.add(trimmed)
    result.push(trimmed)
  }

  return result
}

const mergeUniqueClassification = <T extends string>(first: T[], second: T[]): T[] => {
  const seen = new Set<T>()
  const result: T[] = []

  for (const value of [...first, ...second]) {
    if (!value || seen.has(value)) {
      continue
    }
    seen.add(value)
    result.push(value)
  }

  return result
}

const toTimestamp = (value: string | null | undefined): number | null => {
  if (!value) {
    return null
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return null
  }

  return date.getTime()
}

const pickEarliestString = (first: string | null, second: string | null): string | null => {
  const firstTime = toTimestamp(first)
  const secondTime = toTimestamp(second)

  if (firstTime === null) {
    return second ?? null
  }

  if (secondTime === null) {
    return first ?? null
  }

  return firstTime <= secondTime ? first : second
}

const pickLatestString = (first: string | null, second: string | null): string | null => {
  const firstTime = toTimestamp(first)
  const secondTime = toTimestamp(second)

  if (firstTime === null) {
    return second ?? null
  }

  if (secondTime === null) {
    return first ?? null
  }

  return firstTime >= secondTime ? first : second
}

const extractYear = (value: string | null | undefined): number | null => {
  if (!value || value.length < 4) {
    return null
  }

  const parsed = Number.parseInt(value.slice(0, 4), 10)
  return Number.isNaN(parsed) ? null : parsed
}

const matchesDateRange = (
  value: string | null | undefined,
  from?: string,
  to?: string
): boolean => {
  if (!from && !to) {
    return true
  }

  const timestamp = toTimestamp(value)
  if (timestamp === null) {
    return false
  }

  if (from) {
    const fromTimestamp = toTimestamp(from)
    if (fromTimestamp !== null && timestamp < fromTimestamp) {
      return false
    }
  }

  if (to) {
    const toTimestampValue = toTimestamp(to)
    if (toTimestampValue !== null && timestamp > toTimestampValue) {
      return false
    }
  }

  return true
}

const matchesScoreRange = (
  value: number | null,
  min?: number,
  max?: number,
  floor = Number.NEGATIVE_INFINITY,
  ceiling = Number.POSITIVE_INFINITY
): boolean => {
  if (min === undefined && max === undefined) {
    return true
  }

  if (typeof value !== 'number' || Number.isNaN(value)) {
    return false
  }

  const lowerBound = min ?? floor
  const upperBound = max ?? ceiling
  return value >= lowerBound && value <= upperBound
}

const sortByChronology = (a: KevEntry, b: KevEntry): number => {
  const aTime = toTimestamp(a.dateAdded) ?? Number.NEGATIVE_INFINITY
  const bTime = toTimestamp(b.dateAdded) ?? Number.NEGATIVE_INFINITY

  if (bTime !== aTime) {
    return bTime - aTime
  }

  return a.cveId.localeCompare(b.cveId)
}

const toKevEntry = (row: KevRow): KevEntry => {
  const cveId = normaliseCve(row.cve_id)
  const notes = parseJsonArray(row.notes)
  const cwes = parseJsonArray(row.cwes)
  const domainCategories = parseJsonArray(row.domain_categories) as KevEntry['domainCategories']
  const exploitLayers = parseJsonArray(row.exploit_layers) as KevEntry['exploitLayers']
  const vulnerabilityCategories = parseJsonArray(row.vulnerability_categories) as KevEntry['vulnerabilityCategories']
  const normalised = normaliseVendorProduct({ vendor: row.vendor, product: row.product })

  return {
    id: `kev:${cveId}`,
    cveId,
    sources: ['kev'],
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    vulnerabilityName: ensureString(row.vulnerability_name, cveId || DEFAULT_VULNERABILITY),
    description: row.description ?? '',
    requiredAction: row.required_action ?? null,
    dateAdded: row.date_added ?? '',
    dueDate: row.due_date ?? null,
    ransomwareUse: row.ransomware_use ?? null,
    notes,
    cwes,
    cvssScore: typeof row.cvss_score === 'number' ? row.cvss_score : null,
    cvssVector: row.cvss_vector ?? null,
    cvssVersion: row.cvss_version ?? null,
    cvssSeverity:
      typeof row.cvss_severity === 'string'
        ? (row.cvss_severity as KevEntry['cvssSeverity'])
        : null,
    epssScore: null,
    assigner: null,
    datePublished: row.date_added ?? null,
    dateUpdated: row.updated_at ?? null,
    exploitedSince: row.date_added ?? null,
    sourceUrl: null,
    references: [],
    aliases: [cveId],
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed: row.internet_exposed === 1
  }
}

const toEnisaEntry = (row: EnisaRow): KevEntry | null => {
  if (!row.cve_id) {
    return null
  }

  const cveId = normaliseCve(row.cve_id)
  const references = parseJsonArray(row.reference_links)
  const aliases = parseAliasArray(row.aliases)
  const domainCategories = parseJsonArray(row.domain_categories) as KevEntry['domainCategories']
  const exploitLayers = parseJsonArray(row.exploit_layers) as KevEntry['exploitLayers']
  const vulnerabilityCategories = parseJsonArray(row.vulnerability_categories) as KevEntry['vulnerabilityCategories']
  const normalised = normaliseVendorProduct({ vendor: row.vendor, product: row.product })

  return {
    id: `enisa:${row.enisa_id}`,
    cveId,
    sources: ['enisa'],
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    vulnerabilityName: ensureString(row.vulnerability_name, aliases[0] ?? cveId ?? DEFAULT_VULNERABILITY),
    description: row.description ?? '',
    requiredAction: null,
    dateAdded: row.exploited_since ?? row.date_published ?? '',
    dueDate: null,
    ransomwareUse: null,
    notes: [],
    cwes: [],
    cvssScore: typeof row.cvss_score === 'number' ? row.cvss_score : null,
    cvssVector: row.cvss_vector ?? null,
    cvssVersion: row.cvss_version ?? null,
    cvssSeverity:
      typeof row.cvss_severity === 'string'
        ? (row.cvss_severity as KevEntry['cvssSeverity'])
        : null,
    epssScore: typeof row.epss_score === 'number' ? row.epss_score : null,
    assigner: row.assigner ?? null,
    datePublished: row.date_published ?? null,
    dateUpdated: row.date_updated ?? null,
    exploitedSince: row.exploited_since ?? null,
    sourceUrl: row.source_url ?? null,
    references,
    aliases: aliases.length ? aliases : [cveId],
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed: row.internet_exposed === 1
  }
}

const mergeEntry = (existing: KevEntry, incoming: KevEntry): KevEntry => {
  const sources = existing.sources.slice()
  for (const source of incoming.sources) {
    if (!sources.includes(source)) {
      sources.push(source)
    }
  }

  const vendor =
    existing.vendor !== DEFAULT_VENDOR ? existing.vendor : incoming.vendor
  const product =
    existing.product !== DEFAULT_PRODUCT ? existing.product : incoming.product
  const normalised = normaliseVendorProduct({ vendor, product })
  const vulnerabilityName =
    existing.vulnerabilityName !== DEFAULT_VULNERABILITY
      ? existing.vulnerabilityName
      : incoming.vulnerabilityName

  const description =
    existing.description?.length ?? 0 >= (incoming.description?.length ?? 0)
      ? existing.description
      : incoming.description

  const requiredAction = existing.requiredAction ?? incoming.requiredAction ?? null
  const dateAdded = pickEarliestString(existing.dateAdded, incoming.dateAdded) ?? ''
  const dueDate = existing.dueDate ?? incoming.dueDate ?? null
  const ransomwareUse = existing.ransomwareUse ?? incoming.ransomwareUse ?? null
  const notes = mergeUniqueStrings(existing.notes, incoming.notes)
  const cwes = mergeUniqueStrings(existing.cwes, incoming.cwes)

  const cvssScore = existing.cvssScore ?? incoming.cvssScore ?? null
  const cvssVector = existing.cvssVector ?? incoming.cvssVector ?? null
  const cvssVersion = existing.cvssVersion ?? incoming.cvssVersion ?? null
  const cvssSeverity = existing.cvssSeverity ?? incoming.cvssSeverity ?? null

  const epssScore = existing.epssScore ?? incoming.epssScore ?? null
  const assigner = existing.assigner ?? incoming.assigner ?? null

  const datePublished = pickEarliestString(existing.datePublished, incoming.datePublished)
  const dateUpdated = pickLatestString(existing.dateUpdated, incoming.dateUpdated)
  const exploitedSince = pickEarliestString(existing.exploitedSince, incoming.exploitedSince)
  const sourceUrl = existing.sourceUrl ?? incoming.sourceUrl ?? null
  const references = mergeUniqueStrings(existing.references, incoming.references)
  const aliases = mergeUniqueStrings(existing.aliases, incoming.aliases).map(alias => alias.toUpperCase())

  const domainCategories = mergeUniqueClassification(
    existing.domainCategories,
    incoming.domainCategories
  ) as KevEntry['domainCategories']

  const exploitLayers = mergeUniqueClassification(
    existing.exploitLayers,
    incoming.exploitLayers
  ) as KevEntry['exploitLayers']

  const vulnerabilityCategories = mergeUniqueClassification(
    existing.vulnerabilityCategories,
    incoming.vulnerabilityCategories
  ) as KevEntry['vulnerabilityCategories']

  return {
    ...existing,
    sources,
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    vulnerabilityName,
    description,
    requiredAction,
    dateAdded,
    dueDate,
    ransomwareUse,
    notes,
    cwes,
    cvssScore,
    cvssVector,
    cvssVersion,
    cvssSeverity,
    epssScore,
    assigner,
    datePublished,
    dateUpdated,
    exploitedSince,
    sourceUrl,
    references,
    aliases,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed: existing.internetExposed || incoming.internetExposed
  }
}

const buildCatalogEntries = (kevEntries: KevEntry[], enisaEntries: KevEntry[]): KevEntry[] => {
  const merged = new Map<string, KevEntry>()

  const add = (entry: KevEntry) => {
    const key = entry.cveId.toUpperCase()
    const existing = merged.get(key)
    if (!existing) {
      merged.set(key, {
        ...entry,
        id: `catalog:${key}`,
        cveId: key,
        aliases: mergeUniqueStrings(entry.aliases, [key]).map(alias => alias.toUpperCase())
      })
      return
    }

    merged.set(key, mergeEntry(existing, entry))
  }

  kevEntries.forEach(add)
  enisaEntries.forEach(add)

  const entries = Array.from(merged.values())
  entries.sort(sortByChronology)
  return entries
}

const normaliseQuery = (raw: Record<string, unknown>): CatalogQuery => {
  const getString = (key: string): string | undefined => {
    const value = raw[key]
    return typeof value === 'string' && value.trim() ? value.trim() : undefined
  }

  const getInt = (key: string): number | undefined => {
    const value = raw[key]
    if (typeof value === 'number' && Number.isFinite(value)) {
      return Math.trunc(value)
    }
    if (typeof value === 'string' && value.trim()) {
      const parsed = Number.parseInt(value.trim(), 10)
      return Number.isNaN(parsed) ? undefined : parsed
    }
    return undefined
  }

  const getFloat = (key: string): number | undefined => {
    const value = raw[key]
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value
    }
    if (typeof value === 'string' && value.trim()) {
      const parsed = Number.parseFloat(value.trim())
      return Number.isNaN(parsed) ? undefined : parsed
    }
    return undefined
  }

  const getList = (key: string): string[] | undefined => {
    const value = raw[key]

    const toItems = (source: unknown): string[] => {
      if (typeof source === 'string') {
        return source
          .split(',')
          .map(item => item.trim())
          .filter(Boolean)
      }

      if (Array.isArray(source)) {
        return source
          .map(item => (typeof item === 'string' ? item.trim() : ''))
          .filter(Boolean)
      }

      return []
    }

    const items = toItems(value)
    if (!items.length) {
      return undefined
    }

    return Array.from(new Set(items))
  }

  const filters: CatalogQuery = {}

  const search = getString('search')
  if (search) {
    filters.search = search
  }

  const ownedOnly = getString('ownedOnly')
  if (ownedOnly) {
    filters.ownedOnly = ownedOnly.toLowerCase() === 'true'
  }

  const vendor = getString('vendor')
  const vendors = getList('vendors')
  const vendorKeys = Array.from(new Set([...(vendor ? [vendor] : []), ...(vendors ?? [])])).filter(Boolean)
  if (vendorKeys.length) {
    filters.vendorKeys = vendorKeys
  }

  const product = getString('product')
  const products = getList('products')
  const productKeys = Array.from(new Set([...(product ? [product] : []), ...(products ?? [])])).filter(Boolean)
  if (productKeys.length) {
    filters.productKeys = productKeys
  }

  const domain = getString('domain') as KevDomainCategory | undefined
  if (domain) {
    filters.domain = domain
  }

  const exploit = getString('exploit') as KevExploitLayer | undefined
  if (exploit) {
    filters.exploit = exploit
  }

  const vulnerability = getString('vulnerability') as KevVulnerabilityCategory | undefined
  if (vulnerability) {
    filters.vulnerability = vulnerability
  }

  const startYear = getInt('startYear')
  const endYear = getInt('endYear')
  if (typeof startYear === 'number' && typeof endYear === 'number') {
    filters.startYear = startYear
    filters.endYear = endYear
  }

  const wellKnownOnly = raw['wellKnownOnly']
  if (wellKnownOnly === 'true' || wellKnownOnly === '1' || wellKnownOnly === true) {
    filters.wellKnownOnly = true
  }

  const ransomwareOnly = raw['ransomwareOnly']
  if (ransomwareOnly === 'true' || ransomwareOnly === '1' || ransomwareOnly === true) {
    filters.ransomwareOnly = true
  }

  const internetExposedOnly = raw['internetExposedOnly']
  if (
    internetExposedOnly === 'true' ||
    internetExposedOnly === '1' ||
    internetExposedOnly === true
  ) {
    filters.internetExposedOnly = true
  }

  const source = getString('source')
  if (source === 'kev' || source === 'enisa') {
    filters.source = source
  }

  const cvssMin = getFloat('cvssMin')
  if (cvssMin !== undefined) {
    filters.cvssMin = Math.max(0, Math.min(10, cvssMin))
  }

  const cvssMax = getFloat('cvssMax')
  if (cvssMax !== undefined) {
    filters.cvssMax = Math.max(0, Math.min(10, cvssMax))
  }

  const epssMin = getFloat('epssMin')
  if (epssMin !== undefined) {
    filters.epssMin = Math.max(0, Math.min(100, epssMin))
  }

  const epssMax = getFloat('epssMax')
  if (epssMax !== undefined) {
    filters.epssMax = Math.max(0, Math.min(100, epssMax))
  }

  const fromDate = getString('fromDate')
  if (fromDate) {
    filters.fromDate = fromDate
  }

  const toDate = getString('toDate')
  if (toDate) {
    filters.toDate = toDate
  }

  const fromUpdatedDate = getString('fromUpdatedDate')
  if (fromUpdatedDate) {
    filters.fromUpdatedDate = fromUpdatedDate
  }

  const toUpdatedDate = getString('toUpdatedDate')
  if (toUpdatedDate) {
    filters.toUpdatedDate = toUpdatedDate
  }

  return filters
}

const applyFilters = (entries: KevEntry[], filters: CatalogQuery): KevEntry[] => {
  const searchTerm = filters.search?.toLowerCase()

  const filtered = entries.filter(entry => {
    if (filters.source && !entry.sources.includes(filters.source)) {
      return false
    }

    if (filters.internetExposedOnly && !entry.internetExposed) {
      return false
    }

    const vendorKeys = filters.vendorKeys ?? (filters.vendor ? [filters.vendor] : [])
    if (vendorKeys.length && !vendorKeys.includes(entry.vendorKey)) {
      return false
    }

    const productKeys = filters.productKeys ?? (filters.product ? [filters.product] : [])
    if (filters.ownedOnly && !productKeys.length) {
      return false
    }
    if (productKeys.length && !productKeys.includes(entry.productKey)) {
      return false
    }

    if (filters.domain && !entry.domainCategories.includes(filters.domain)) {
      return false
    }

    if (filters.exploit && !entry.exploitLayers.includes(filters.exploit)) {
      return false
    }

    if (filters.vulnerability && !entry.vulnerabilityCategories.includes(filters.vulnerability)) {
      return false
    }

    if (filters.ransomwareOnly) {
      const value = entry.ransomwareUse?.toLowerCase() ?? ''
      if (!value.includes('known')) {
        return false
      }
    }

    if (filters.wellKnownOnly && !lookupCveName(entry.cveId)) {
      return false
    }

    if (typeof filters.startYear === 'number' && typeof filters.endYear === 'number') {
      const year = extractYear(entry.dateAdded)
      if (year !== null && (year < filters.startYear || year > filters.endYear)) {
        return false
      }
    }

    if (searchTerm) {
      const haystack = [
        entry.cveId,
        entry.vendor,
        entry.product,
        entry.vulnerabilityName,
        entry.description
      ]
      const matches = haystack.some(value => value?.toLowerCase().includes(searchTerm))
      if (!matches) {
        return false
      }
    }

    if (!matchesDateRange(entry.dateAdded, filters.fromDate, filters.toDate)) {
      return false
    }

    if (!matchesDateRange(entry.dateUpdated, filters.fromUpdatedDate, filters.toUpdatedDate)) {
      return false
    }

    if (!matchesScoreRange(entry.cvssScore, filters.cvssMin, filters.cvssMax, 0, 10)) {
      return false
    }

    if (!matchesScoreRange(entry.epssScore, filters.epssMin, filters.epssMax, 0, 100)) {
      return false
    }

    return true
  })

  filtered.sort(sortByChronology)
  return filtered
}

const omitFilters = (
  filters: CatalogQuery,
  keys: Array<keyof CatalogQuery>
): CatalogQuery => {
  const next: CatalogQuery = { ...filters }
  for (const key of keys) {
    if (filters.ownedOnly && (key === 'product' || key === 'productKeys')) {
      continue
    }
    delete next[key]
  }
  return next
}

type AggregatedValue =
  | string
  | {
      key: string
      name: string
      vendorKey?: string
      vendorName?: string
    }

const aggregateCounts = (
  entries: KevEntry[],
  accessor: (entry: KevEntry) => AggregatedValue | AggregatedValue[]
): KevCountDatum[] => {
  const totals = new Map<
    string,
    { name: string; count: number; vendorKey?: string; vendorName?: string }
  >()

  const toDatum = (
    value: AggregatedValue
  ): { key: string; name: string; vendorKey?: string; vendorName?: string } => {
    if (typeof value === 'string') {
      return { key: value, name: value }
    }
    return value
  }

  for (const entry of entries) {
    const raw = accessor(entry)
    const values = Array.isArray(raw) ? raw : [raw]

    for (const value of values) {
      const datum = toDatum(value)
      if (!datum.key || !datum.name || datum.name === 'Other') {
        continue
      }

      const existing = totals.get(datum.key)
      if (existing) {
        existing.count += 1
      } else {
        totals.set(datum.key, {
          name: datum.name,
          count: 1,
          vendorKey: datum.vendorKey,
          vendorName: datum.vendorName
        })
      }
    }
  }

  return Array.from(totals.entries())
    .map(([key, value]) => ({
      key,
      name: value.name,
      count: value.count,
      vendorKey: value.vendorKey,
      vendorName: value.vendorName
    }))
    .sort((a, b) => {
      if (b.count === a.count) {
        return a.name.localeCompare(b.name)
      }
      return b.count - a.count
    })
}

const getCatalogBounds = (
  entries: KevEntry[]
): { earliest: string | null; latest: string | null } => {
  let earliest: { timestamp: number; value: string } | null = null
  let latest: { timestamp: number; value: string } | null = null

  for (const entry of entries) {
    const timestamp = toTimestamp(entry.dateAdded)
    if (timestamp === null || !entry.dateAdded) {
      continue
    }

    if (!earliest || timestamp < earliest.timestamp) {
      earliest = { timestamp, value: entry.dateAdded }
    }

    if (!latest || timestamp > latest.timestamp) {
      latest = { timestamp, value: entry.dateAdded }
    }
  }

  return {
    earliest: earliest?.value ?? null,
    latest: latest?.value ?? null
  }
}

const computeUpdatedAt = (entries: KevEntry[]): string => {
  const candidates = [
    getMetadata('dateReleased'),
    getMetadata('lastImportAt'),
    getMetadata('enisa.lastUpdatedAt'),
    getMetadata('enisa.lastImportAt')
  ].filter((value): value is string => typeof value === 'string' && value.length > 0)

  if (candidates.length > 0) {
    candidates.sort()
    return candidates[candidates.length - 1] ?? ''
  }

  const entryDates = entries
    .map(entry => entry.dateUpdated ?? entry.dateAdded ?? null)
    .filter((value): value is string => typeof value === 'string' && value.length > 0)
    .sort()

  return entryDates.at(-1) ?? ''
}

export default defineEventHandler(async (event): Promise<KevResponse> => {
  const db = getDatabase()
  const kevRows = db
    .prepare<KevRow>(
      `SELECT
        cve_id,
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
        domain_categories,
        exploit_layers,
        vulnerability_categories,
        internet_exposed,
        updated_at
      FROM kev_entries`
    )
    .all() as KevRow[]

  const enisaRows = db
    .prepare<EnisaRow>(
      `SELECT
        enisa_id,
        cve_id,
        vendor,
        product,
        vulnerability_name,
        description,
        assigner,
        date_published,
        date_updated,
        exploited_since,
        cvss_score,
        cvss_vector,
        cvss_version,
        cvss_severity,
        epss_score,
        reference_links,
        aliases,
        domain_categories,
        exploit_layers,
        vulnerability_categories,
        source_url,
        internet_exposed,
        updated_at
      FROM enisa_entries`
    )
    .all() as EnisaRow[]

  const kevEntries = kevRows.map(toKevEntry)
  const enisaEntries = enisaRows
    .map(toEnisaEntry)
    .filter((entry): entry is KevEntry => entry !== null)

  const catalogEntries = buildCatalogEntries(kevEntries, enisaEntries)

  const filters = normaliseQuery(getQuery(event))
  const filteredEntries = applyFilters(catalogEntries, filters)

  const counts = {
    domain: aggregateCounts(
      applyFilters(
        catalogEntries,
        omitFilters(filters, [
          'domain',
          'exploit',
          'vulnerability',
          'vendor',
          'vendorKeys',
          'product',
          'productKeys'
        ])
      ),
      entry => entry.domainCategories
    ),
    exploit: aggregateCounts(
      applyFilters(
        catalogEntries,
        omitFilters(filters, [
          'exploit',
          'vulnerability',
          'vendor',
          'vendorKeys',
          'product',
          'productKeys'
        ])
      ),
      entry => entry.exploitLayers
    ),
    vulnerability: aggregateCounts(
      applyFilters(
        catalogEntries,
        omitFilters(filters, ['vulnerability', 'vendor', 'vendorKeys', 'product', 'productKeys'])
      ),
      entry => entry.vulnerabilityCategories
    ),
    vendor: aggregateCounts(
      applyFilters(
        catalogEntries,
        omitFilters(filters, ['vendor', 'vendorKeys', 'product', 'productKeys'])
      ),
      entry => ({ key: entry.vendorKey, name: entry.vendor })
    ),
    product: aggregateCounts(
      applyFilters(
        catalogEntries,
        omitFilters(filters, ['product', 'productKeys'])
      ),
      entry => ({
        key: entry.productKey,
        name: entry.product,
        vendorKey: entry.vendorKey,
        vendorName: entry.vendor
      })
    )
  }

  const catalogBounds = getCatalogBounds(catalogEntries)
  const updatedAt = computeUpdatedAt(catalogEntries)

  return {
    updatedAt,
    entries: filteredEntries,
    counts,
    catalogBounds
  }
})
