import { getQuery } from 'h3'
import type {
  CatalogSource,
  KevCountDatum,
  KevDomainCategory,
  KevEntrySummary,
  KevExploitLayer,
  KevResponse,
  KevVulnerabilityCategory
} from '~/types'
import { catalogRowToSummary, type CatalogSummaryRow } from '../utils/catalog'
import { getDatabase, getMetadata } from '../utils/sqlite'

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
  limit?: number
}

type SqlFilter = {
  where: string[]
  params: Record<string, unknown>
}

const toTimestamp = (value?: string): number | null => {
  if (!value) {
    return null
  }
  const timestamp = Date.parse(value)
  if (Number.isNaN(timestamp)) {
    return null
  }
  return timestamp
}

const DEFAULT_ENTRY_LIMIT = 250

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

  const limit = getInt('limit')
  if (typeof limit === 'number' && limit > 0) {
    filters.limit = Math.max(1, Math.min(500, limit))
  }

  return filters
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

const buildSqlFilter = (filters: CatalogQuery): SqlFilter => {
  const where: string[] = []
  const params: Record<string, unknown> = {}
  let paramIndex = 0

  const addParam = (value: unknown): string => {
    const key = `p${paramIndex}`
    paramIndex += 1
    params[key] = value
    return `@${key}`
  }

  if (filters.search) {
    const key = addParam(`%${filters.search.toLowerCase()}%`)
    where.push(
      `(
        LOWER(ce.cve_id) LIKE ${key}
        OR LOWER(ce.vendor) LIKE ${key}
        OR LOWER(ce.product) LIKE ${key}
        OR LOWER(ce.vulnerability_name) LIKE ${key}
        OR LOWER(ce.description) LIKE ${key}
      )`
    )
  }

  if (filters.source === 'kev') {
    where.push('ce.has_source_kev = 1')
  } else if (filters.source === 'enisa') {
    where.push('ce.has_source_enisa = 1')
  }

  if (filters.internetExposedOnly) {
    where.push('ce.internet_exposed = 1')
  }

  const vendorKeys = filters.vendorKeys ?? (filters.vendor ? [filters.vendor] : [])
  if (vendorKeys.length) {
    const placeholders = vendorKeys.map(value => addParam(value))
    where.push(`ce.vendor_key IN (${placeholders.join(', ')})`)
  }

  const productKeys = filters.productKeys ?? (filters.product ? [filters.product] : [])
  if (productKeys.length) {
    const placeholders = productKeys.map(value => addParam(value))
    where.push(`ce.product_key IN (${placeholders.join(', ')})`)
  }

  if (filters.domain) {
    const key = addParam(filters.domain)
    where.push(
      `EXISTS (
        SELECT 1 FROM catalog_entry_dimensions d
        WHERE d.cve_id = ce.cve_id
          AND d.dimension = 'domain'
          AND d.value = ${key}
      )`
    )
  }

  if (filters.exploit) {
    const key = addParam(filters.exploit)
    where.push(
      `EXISTS (
        SELECT 1 FROM catalog_entry_dimensions d
        WHERE d.cve_id = ce.cve_id
          AND d.dimension = 'exploit'
          AND d.value = ${key}
      )`
    )
  }

  if (filters.vulnerability) {
    const key = addParam(filters.vulnerability)
    where.push(
      `EXISTS (
        SELECT 1 FROM catalog_entry_dimensions d
        WHERE d.cve_id = ce.cve_id
          AND d.dimension = 'vulnerability'
          AND d.value = ${key}
      )`
    )
  }

  if (filters.ransomwareOnly) {
    where.push('ce.has_known_ransomware = 1')
  }

  if (filters.wellKnownOnly) {
    where.push('ce.is_well_known = 1')
  }

  if (typeof filters.startYear === 'number' && typeof filters.endYear === 'number') {
    const startKey = addParam(filters.startYear)
    const endKey = addParam(filters.endYear)
    where.push(
      `(ce.date_added_year IS NULL OR (ce.date_added_year >= ${startKey} AND ce.date_added_year <= ${endKey}))`
    )
  }

  if (filters.fromDate) {
    const timestamp = toTimestamp(filters.fromDate)
    if (timestamp !== null) {
      const key = addParam(timestamp)
      where.push('ce.date_added_ts IS NOT NULL AND ce.date_added_ts >= ' + key)
    }
  }

  if (filters.toDate) {
    const timestamp = toTimestamp(filters.toDate)
    if (timestamp !== null) {
      const key = addParam(timestamp)
      where.push('ce.date_added_ts IS NOT NULL AND ce.date_added_ts <= ' + key)
    }
  }

  if (filters.fromUpdatedDate) {
    const timestamp = toTimestamp(filters.fromUpdatedDate)
    if (timestamp !== null) {
      const key = addParam(timestamp)
      where.push('ce.date_updated_ts IS NOT NULL AND ce.date_updated_ts >= ' + key)
    }
  }

  if (filters.toUpdatedDate) {
    const timestamp = toTimestamp(filters.toUpdatedDate)
    if (timestamp !== null) {
      const key = addParam(timestamp)
      where.push('ce.date_updated_ts IS NOT NULL AND ce.date_updated_ts <= ' + key)
    }
  }

  if (filters.cvssMin !== undefined) {
    const key = addParam(filters.cvssMin)
    where.push('ce.cvss_score IS NOT NULL AND ce.cvss_score >= ' + key)
  }

  if (filters.cvssMax !== undefined) {
    const key = addParam(filters.cvssMax)
    where.push('ce.cvss_score IS NOT NULL AND ce.cvss_score <= ' + key)
  }

  if (filters.epssMin !== undefined) {
    const key = addParam(filters.epssMin)
    where.push('ce.epss_score IS NOT NULL AND ce.epss_score >= ' + key)
  }

  if (filters.epssMax !== undefined) {
    const key = addParam(filters.epssMax)
    where.push('ce.epss_score IS NOT NULL AND ce.epss_score <= ' + key)
  }

  return { where, params }
}

const buildWhereClause = (where: string[]): string => {
  if (!where.length) {
    return ''
  }
  return 'WHERE ' + where.join('\n  AND ')
}

const queryEntries = (
  db: ReturnType<typeof getDatabase>,
  filters: CatalogQuery,
  limitOverride?: number
): KevEntrySummary[] => {
  const { where, params } = buildSqlFilter(filters)
  const whereClause = buildWhereClause(where)
  const limit = Math.max(1, Math.min(500, limitOverride ?? filters.limit ?? DEFAULT_ENTRY_LIMIT))
  const rows = db
    .prepare<CatalogSummaryRow>(
      `SELECT
        ce.cve_id,
        ce.entry_id,
        ce.sources,
        ce.vendor,
        ce.vendor_key,
        ce.product,
        ce.product_key,
        ce.vulnerability_name,
        ce.description,
        ce.due_date,
        ce.date_added,
        ce.ransomware_use,
        ce.cvss_score,
        ce.cvss_severity,
        ce.epss_score,
        ce.domain_categories,
        ce.exploit_layers,
        ce.vulnerability_categories,
        ce.internet_exposed
      FROM catalog_entries ce
      ${whereClause}
      ORDER BY (ce.date_added_ts IS NULL) ASC, ce.date_added_ts DESC, ce.cve_id ASC
      LIMIT @limit`
    )
    .all({ ...params, limit }) as CatalogSummaryRow[]

  return rows.map(catalogRowToSummary)
}

const queryDimensionCounts = (
  db: ReturnType<typeof getDatabase>,
  filters: CatalogQuery,
  dimension: 'domain' | 'exploit' | 'vulnerability'
): KevCountDatum[] => {
  const { where, params } = buildSqlFilter(filters)
  const whereClause = buildWhereClause(where)
  const rows = db
    .prepare<{ key: string; name: string; count: number }>(
      `WITH filtered AS (
        SELECT ce.cve_id FROM catalog_entries ce
        ${whereClause}
      )
      SELECT d.value AS key, d.name AS name, COUNT(*) AS count
      FROM catalog_entry_dimensions d
      JOIN filtered f ON f.cve_id = d.cve_id
      WHERE d.dimension = '${dimension}'
      GROUP BY d.value, d.name
      ORDER BY count DESC, name ASC`
    )
    .all(params) as Array<{ key: string; name: string; count: number }>

  return rows.map(row => ({ key: row.key, name: row.name, count: row.count }))
}

const queryVendorCounts = (
  db: ReturnType<typeof getDatabase>,
  filters: CatalogQuery
): KevCountDatum[] => {
  const { where, params } = buildSqlFilter(filters)
  const whereClause = buildWhereClause(where)
  const rows = db
    .prepare<{ key: string; name: string; count: number }>(
      `WITH filtered AS (
        SELECT ce.vendor_key, ce.vendor
        FROM catalog_entries ce
        ${whereClause}
      )
      SELECT vendor_key AS key, MAX(vendor) AS name, COUNT(*) AS count
      FROM filtered
      WHERE vendor_key != ''
      GROUP BY vendor_key
      HAVING MAX(vendor) != 'Other'
      ORDER BY count DESC, name ASC`
    )
    .all(params) as Array<{ key: string; name: string; count: number }>

  return rows.map(row => ({ key: row.key, name: row.name, count: row.count }))
}

const queryProductCounts = (
  db: ReturnType<typeof getDatabase>,
  filters: CatalogQuery
): KevCountDatum[] => {
  const { where, params } = buildSqlFilter(filters)
  const whereClause = buildWhereClause(where)
  const rows = db
    .prepare<{
      key: string
      name: string
      count: number
      vendorKey: string
      vendorName: string
    }>(
      `WITH filtered AS (
        SELECT ce.product_key, ce.product, ce.vendor_key, ce.vendor
        FROM catalog_entries ce
        ${whereClause}
      )
      SELECT
        product_key AS key,
        MAX(product) AS name,
        MAX(vendor_key) AS vendorKey,
        MAX(vendor) AS vendorName,
        COUNT(*) AS count
      FROM filtered
      WHERE product_key != ''
      GROUP BY product_key
      HAVING MAX(product) != 'Other'
      ORDER BY count DESC, name ASC`
    )
    .all(params) as Array<{
      key: string
      name: string
      count: number
      vendorKey: string
      vendorName: string
    }>

  return rows.map(row => ({
    key: row.key,
    name: row.name,
    count: row.count,
    vendorKey: row.vendorKey,
    vendorName: row.vendorName
  }))
}

const countEntries = (
  db: ReturnType<typeof getDatabase>,
  filters: CatalogQuery
): number => {
  const { where, params } = buildSqlFilter(filters)
  const whereClause = buildWhereClause(where)
  const row = db
    .prepare<{ count: number }>(
      `SELECT COUNT(*) AS count FROM catalog_entries ce ${whereClause}`
    )
    .get(params) as { count: number } | undefined

  return row?.count ?? 0
}

const getCatalogBounds = (
  db: ReturnType<typeof getDatabase>
): { earliest: string | null; latest: string | null } => {
  const earliest = getMetadata('catalog.earliestDate')
  const latest = getMetadata('catalog.latestDate')

  if (earliest || latest) {
    return {
      earliest: earliest ?? null,
      latest: latest ?? null
    }
  }

  const row = db
    .prepare<{ earliest: string | null; latest: string | null }>(
      `SELECT MIN(date_added) AS earliest, MAX(date_added) AS latest FROM catalog_entries`
    )
    .get() as { earliest: string | null; latest: string | null }

  return {
    earliest: row?.earliest ?? null,
    latest: row?.latest ?? null
  }
}

const computeUpdatedAt = (db: ReturnType<typeof getDatabase>): string => {
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

  const row = db
    .prepare<{ latest: string | null }>(
      `SELECT MAX(COALESCE(date_updated, date_added)) AS latest FROM catalog_entries`
    )
    .get() as { latest: string | null }

  return row?.latest ?? ''
}

export default defineEventHandler(async (event): Promise<KevResponse> => {
  const filters = normaliseQuery(getQuery(event))
  const entryLimit = Math.max(1, Math.min(500, filters.limit ?? DEFAULT_ENTRY_LIMIT))
  const db = getDatabase()

  if (filters.ownedOnly && !(filters.productKeys?.length ?? 0)) {
    return {
      updatedAt: computeUpdatedAt(db),
      entries: [],
      counts: {
        domain: [],
        exploit: [],
        vulnerability: [],
        vendor: [],
        product: []
      },
      catalogBounds: getCatalogBounds(db),
      totalEntries: 0,
      entryLimit
    }
  }

  const entries = queryEntries(db, filters, entryLimit)
  const totalEntries = countEntries(db, filters)

  const counts = {
    domain: queryDimensionCounts(
      db,
      omitFilters(filters, [
        'domain',
        'exploit',
        'vulnerability',
        'vendor',
        'vendorKeys',
        'product',
        'productKeys'
      ]),
      'domain'
    ),
    exploit: queryDimensionCounts(
      db,
      omitFilters(filters, [
        'exploit',
        'vulnerability',
        'vendor',
        'vendorKeys',
        'product',
        'productKeys'
      ]),
      'exploit'
    ),
    vulnerability: queryDimensionCounts(
      db,
      omitFilters(filters, ['vulnerability', 'vendor', 'vendorKeys', 'product', 'productKeys']),
      'vulnerability'
    ),
    vendor: queryVendorCounts(
      db,
      omitFilters(filters, ['vendor', 'vendorKeys', 'product', 'productKeys'])
    ),
    product: queryProductCounts(
      db,
      omitFilters(filters, ['product', 'productKeys'])
    )
  }

  const catalogBounds = getCatalogBounds(db)
  const updatedAt = computeUpdatedAt(db)

  return {
    updatedAt,
    entries,
    counts,
    catalogBounds,
    totalEntries,
    entryLimit
  }
})
