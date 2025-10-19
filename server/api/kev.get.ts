import { getQuery } from 'h3'
import { and, eq, inArray, ne, sql, type SQL } from 'drizzle-orm'
import type {
  CatalogSource,
  KevCountDatum,
  KevDomainCategory,
  KevEntrySummary,
  KevExploitLayer,
  KevResponse,
  KevVulnerabilityCategory
} from '~/types'
import { tables } from '../database/client'
import { catalogRowToSummary, type CatalogSummaryRow } from '../utils/catalog'
import { getDatabase, getMetadata, type DrizzleDatabase } from '../utils/sqlite'

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
const MAX_ENTRY_LIMIT = 10_000

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
    filters.limit = Math.max(1, Math.min(MAX_ENTRY_LIMIT, limit))
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

const catalogEntries = tables.catalogEntries
const catalogEntryDimensions = tables.catalogEntryDimensions

const buildFilterExpression = (filters: CatalogQuery): SQL<unknown> | undefined => {
  const conditions: SQL<unknown>[] = []

  if (filters.search) {
    const pattern = `%${filters.search.toLowerCase()}%`
    conditions.push(
      sql`(
        lower(${catalogEntries.cveId}) LIKE ${pattern}
        OR lower(${catalogEntries.vendor}) LIKE ${pattern}
        OR lower(${catalogEntries.product}) LIKE ${pattern}
        OR lower(${catalogEntries.vulnerabilityName}) LIKE ${pattern}
        OR lower(${catalogEntries.description}) LIKE ${pattern}
      )`
    )
  }

  if (filters.source === 'kev') {
    conditions.push(eq(catalogEntries.hasSourceKev, 1))
  } else if (filters.source === 'enisa') {
    conditions.push(eq(catalogEntries.hasSourceEnisa, 1))
  }

  if (filters.internetExposedOnly) {
    conditions.push(eq(catalogEntries.internetExposed, 1))
  }

  const vendorKeys = filters.vendorKeys ?? (filters.vendor ? [filters.vendor] : [])
  if (vendorKeys.length) {
    conditions.push(inArray(catalogEntries.vendorKey, vendorKeys))
  }

  const productKeys = filters.productKeys ?? (filters.product ? [filters.product] : [])
  if (productKeys.length) {
    conditions.push(inArray(catalogEntries.productKey, productKeys))
  }

  if (filters.domain) {
    conditions.push(
      sql`EXISTS (
        SELECT 1 FROM ${catalogEntryDimensions}
        WHERE ${catalogEntryDimensions.cveId} = ${catalogEntries.cveId}
          AND ${catalogEntryDimensions.dimension} = 'domain'
          AND ${catalogEntryDimensions.value} = ${filters.domain}
      )`
    )
  }

  if (filters.exploit) {
    conditions.push(
      sql`EXISTS (
        SELECT 1 FROM ${catalogEntryDimensions}
        WHERE ${catalogEntryDimensions.cveId} = ${catalogEntries.cveId}
          AND ${catalogEntryDimensions.dimension} = 'exploit'
          AND ${catalogEntryDimensions.value} = ${filters.exploit}
      )`
    )
  }

  if (filters.vulnerability) {
    conditions.push(
      sql`EXISTS (
        SELECT 1 FROM ${catalogEntryDimensions}
        WHERE ${catalogEntryDimensions.cveId} = ${catalogEntries.cveId}
          AND ${catalogEntryDimensions.dimension} = 'vulnerability'
          AND ${catalogEntryDimensions.value} = ${filters.vulnerability}
      )`
    )
  }

  if (filters.ransomwareOnly) {
    conditions.push(eq(catalogEntries.hasKnownRansomware, 1))
  }

  if (filters.wellKnownOnly) {
    conditions.push(eq(catalogEntries.isWellKnown, 1))
  }

  if (typeof filters.startYear === 'number' && typeof filters.endYear === 'number') {
    conditions.push(
      sql`(${catalogEntries.dateAddedYear} IS NULL OR (${catalogEntries.dateAddedYear} >= ${filters.startYear} AND ${catalogEntries.dateAddedYear} <= ${filters.endYear}))`
    )
  }

  if (filters.fromDate) {
    const timestamp = toTimestamp(filters.fromDate)
    if (timestamp !== null) {
      conditions.push(
        sql`(${catalogEntries.dateAddedTs} IS NOT NULL AND ${catalogEntries.dateAddedTs} >= ${timestamp})`
      )
    }
  }

  if (filters.toDate) {
    const timestamp = toTimestamp(filters.toDate)
    if (timestamp !== null) {
      conditions.push(
        sql`(${catalogEntries.dateAddedTs} IS NOT NULL AND ${catalogEntries.dateAddedTs} <= ${timestamp})`
      )
    }
  }

  if (filters.fromUpdatedDate) {
    const timestamp = toTimestamp(filters.fromUpdatedDate)
    if (timestamp !== null) {
      conditions.push(
        sql`(${catalogEntries.dateUpdatedTs} IS NOT NULL AND ${catalogEntries.dateUpdatedTs} >= ${timestamp})`
      )
    }
  }

  if (filters.toUpdatedDate) {
    const timestamp = toTimestamp(filters.toUpdatedDate)
    if (timestamp !== null) {
      conditions.push(
        sql`(${catalogEntries.dateUpdatedTs} IS NOT NULL AND ${catalogEntries.dateUpdatedTs} <= ${timestamp})`
      )
    }
  }

  if (filters.cvssMin !== undefined) {
    conditions.push(
      sql`(${catalogEntries.cvssScore} IS NOT NULL AND ${catalogEntries.cvssScore} >= ${filters.cvssMin})`
    )
  }

  if (filters.cvssMax !== undefined) {
    conditions.push(
      sql`(${catalogEntries.cvssScore} IS NOT NULL AND ${catalogEntries.cvssScore} <= ${filters.cvssMax})`
    )
  }

  if (filters.epssMin !== undefined) {
    conditions.push(
      sql`(${catalogEntries.epssScore} IS NOT NULL AND ${catalogEntries.epssScore} >= ${filters.epssMin})`
    )
  }

  if (filters.epssMax !== undefined) {
    conditions.push(
      sql`(${catalogEntries.epssScore} IS NOT NULL AND ${catalogEntries.epssScore} <= ${filters.epssMax})`
    )
  }

  if (!conditions.length) {
    return undefined
  }

  return and(...conditions)
}

const queryEntries = (
  db: DrizzleDatabase,
  filters: CatalogQuery,
  limitOverride?: number
): KevEntrySummary[] => {
  const where = buildFilterExpression(filters)
  const limit = Math.max(
    1,
    Math.min(MAX_ENTRY_LIMIT, limitOverride ?? filters.limit ?? DEFAULT_ENTRY_LIMIT)
  )

  let query = db
    .select({
      cve_id: catalogEntries.cveId,
      entry_id: catalogEntries.entryId,
      sources: catalogEntries.sources,
      vendor: catalogEntries.vendor,
      vendor_key: catalogEntries.vendorKey,
      product: catalogEntries.product,
      product_key: catalogEntries.productKey,
      vulnerability_name: catalogEntries.vulnerabilityName,
      description: catalogEntries.description,
      due_date: catalogEntries.dueDate,
      date_added: catalogEntries.dateAdded,
      ransomware_use: catalogEntries.ransomwareUse,
      cvss_score: catalogEntries.cvssScore,
      cvss_severity: catalogEntries.cvssSeverity,
      epss_score: catalogEntries.epssScore,
      domain_categories: catalogEntries.domainCategories,
      exploit_layers: catalogEntries.exploitLayers,
      vulnerability_categories: catalogEntries.vulnerabilityCategories,
      internet_exposed: catalogEntries.internetExposed
    })
    .from(catalogEntries)

  if (where) {
    query = query.where(where)
  }

  const rows = query
    .orderBy(
      sql`(${catalogEntries.dateAddedTs} IS NULL) ASC`,
      sql`${catalogEntries.dateAddedTs} DESC`,
      sql`${catalogEntries.cveId} ASC`
    )
    .limit(limit)
    .all() as CatalogSummaryRow[]

  return rows.map(catalogRowToSummary)
}

const queryDimensionCounts = (
  db: DrizzleDatabase,
  filters: CatalogQuery,
  dimension: 'domain' | 'exploit' | 'vulnerability'
): KevCountDatum[] => {
  const where = buildFilterExpression(filters)

  let filteredQuery = db.select({ cve_id: catalogEntries.cveId }).from(catalogEntries)
  if (where) {
    filteredQuery = filteredQuery.where(where)
  }

  const filtered = filteredQuery.as('filtered')
  const countExpr = sql<number>`COUNT(*)`.as('count')

  const rows = db
    .select({
      key: catalogEntryDimensions.value,
      name: catalogEntryDimensions.name,
      count: countExpr
    })
    .from(catalogEntryDimensions)
    .innerJoin(filtered, eq(filtered.cve_id, catalogEntryDimensions.cveId))
    .where(eq(catalogEntryDimensions.dimension, dimension))
    .groupBy(catalogEntryDimensions.value, catalogEntryDimensions.name)
    .orderBy(sql`count DESC`, sql`${catalogEntryDimensions.name} ASC`)
    .all()

  return rows.map(row => ({ key: row.key, name: row.name, count: row.count }))
}

const queryVendorCounts = (
  db: DrizzleDatabase,
  filters: CatalogQuery
): KevCountDatum[] => {
  const where = buildFilterExpression(filters)

  let filteredQuery = db
    .select({ vendor_key: catalogEntries.vendorKey, vendor: catalogEntries.vendor })
    .from(catalogEntries)

  if (where) {
    filteredQuery = filteredQuery.where(where)
  }

  const filtered = filteredQuery.as('filtered')
  const countExpr = sql<number>`COUNT(*)`.as('count')
  const nameExpr = sql<string>`MAX(${filtered.vendor})`.as('name')

  const rows = db
    .select({ key: filtered.vendor_key, name: nameExpr, count: countExpr })
    .from(filtered)
    .where(ne(filtered.vendor_key, ''))
    .groupBy(filtered.vendor_key)
    .having(sql`MAX(${filtered.vendor}) != 'Other'`)
    .orderBy(sql`count DESC`, sql`name ASC`)
    .all()

  return rows.map(row => ({ key: row.key, name: row.name, count: row.count }))
}

const queryProductCounts = (
  db: DrizzleDatabase,
  filters: CatalogQuery
): KevCountDatum[] => {
  const where = buildFilterExpression(filters)

  let filteredQuery = db
    .select({
      product_key: catalogEntries.productKey,
      product: catalogEntries.product,
      vendor_key: catalogEntries.vendorKey,
      vendor: catalogEntries.vendor
    })
    .from(catalogEntries)

  if (where) {
    filteredQuery = filteredQuery.where(where)
  }

  const filtered = filteredQuery.as('filtered')
  const countExpr = sql<number>`COUNT(*)`.as('count')
  const nameExpr = sql<string>`MAX(${filtered.product})`.as('name')
  const vendorKeyExpr = sql<string>`MAX(${filtered.vendor_key})`.as('vendorKey')
  const vendorNameExpr = sql<string>`MAX(${filtered.vendor})`.as('vendorName')

  const rows = db
    .select({
      key: filtered.product_key,
      name: nameExpr,
      vendorKey: vendorKeyExpr,
      vendorName: vendorNameExpr,
      count: countExpr
    })
    .from(filtered)
    .where(ne(filtered.product_key, ''))
    .groupBy(filtered.product_key)
    .having(sql`MAX(${filtered.product}) != 'Other'`)
    .orderBy(sql`count DESC`, sql`name ASC`)
    .all()

  return rows.map(row => ({
    key: row.key,
    name: row.name,
    count: row.count,
    vendorKey: row.vendorKey,
    vendorName: row.vendorName
  }))
}

const countEntries = (db: DrizzleDatabase, filters: CatalogQuery): number => {
  const where = buildFilterExpression(filters)
  const countExpr = sql<number>`COUNT(*)`.as('count')

  let query = db.select({ count: countExpr }).from(catalogEntries)
  if (where) {
    query = query.where(where)
  }

  const row = query.get()
  return row?.count ?? 0
}

const getCatalogBounds = (
  db: DrizzleDatabase
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
    .select({
      earliest: sql<string | null>`MIN(${catalogEntries.dateAdded})`,
      latest: sql<string | null>`MAX(${catalogEntries.dateAdded})`
    })
    .from(catalogEntries)
    .get()

  return {
    earliest: row?.earliest ?? null,
    latest: row?.latest ?? null
  }
}

const computeUpdatedAt = (db: DrizzleDatabase): string => {
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
    .select({
      latest: sql<string | null>`MAX(COALESCE(${catalogEntries.dateUpdated}, ${catalogEntries.dateAdded}))`
    })
    .from(catalogEntries)
    .get()

  return row?.latest ?? ''
}

export default defineEventHandler(async (event): Promise<KevResponse> => {
  const filters = normaliseQuery(getQuery(event))
  const entryLimit = Math.max(1, Math.min(MAX_ENTRY_LIMIT, filters.limit ?? DEFAULT_ENTRY_LIMIT))
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
    vendor: queryVendorCounts(db, omitFilters(filters, ['vendor', 'vendorKeys', 'product', 'productKeys'])),
    product: queryProductCounts(db, omitFilters(filters, ['product', 'productKeys']))
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
