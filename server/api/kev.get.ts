import { getQuery } from 'h3'
import { and, asc, desc, eq, inArray, ne, sql, type SQL } from 'drizzle-orm'
import { alias } from 'drizzle-orm/sqlite-core'
import type {
  CatalogSource,
  KevCountDatum,
  KevDomainCategory,
  KevEntrySummary,
  KevExploitLayer,
  KevResponse,
  KevVulnerabilityCategory,
  MarketProgramType
} from '~/types'
import { tables } from '../database/client'
import {
  catalogRowToSummary,
  getMarketSignalsForProducts,
  type CatalogSummaryRow
} from '../utils/catalog'
import { getDatabase, getMetadata } from '../utils/sqlite'
import type { DrizzleDatabase } from '../utils/sqlite'

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
  publicExploitOnly?: boolean
  source?: CatalogSource
  cvssMin?: number
  cvssMax?: number
  epssMin?: number
  epssMax?: number
  priceMin?: number
  priceMax?: number
  fromDate?: string
  toDate?: string
  fromUpdatedDate?: string
  toUpdatedDate?: string
  ransomwareOnly?: boolean
  internetExposedOnly?: boolean
  limit?: number
  marketProgramType?: MarketProgramType
}

type Condition = SQL<unknown>

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

const DEFAULT_ENTRY_LIMIT = 25
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

  const publicExploitOnly = raw['publicExploitOnly']
  if (publicExploitOnly === 'true' || publicExploitOnly === '1' || publicExploitOnly === true) {
    filters.publicExploitOnly = true
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
  if (
    source === 'kev' ||
    source === 'enisa' ||
    source === 'historic' ||
    source === 'metasploit' ||
    source === 'poc'
  ) {
    filters.source = source
  }

  const marketProgramType = getString('marketProgramType') as MarketProgramType | undefined
  if (
    marketProgramType === 'exploit-broker' ||
    marketProgramType === 'bug-bounty' ||
    marketProgramType === 'other'
  ) {
    filters.marketProgramType = marketProgramType
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

  const priceMin = getFloat('priceMin')
  if (priceMin !== undefined && Number.isFinite(priceMin)) {
    filters.priceMin = Math.max(0, priceMin)
  }

  const priceMax = getFloat('priceMax')
  if (priceMax !== undefined && Number.isFinite(priceMax)) {
    filters.priceMax = Math.max(0, priceMax)
  }

  if (
    filters.priceMin !== undefined &&
    filters.priceMax !== undefined &&
    filters.priceMin > filters.priceMax
  ) {
    const [min, max] = [filters.priceMax, filters.priceMin]
    filters.priceMin = min
    filters.priceMax = max
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

const buildConditions = (filters: CatalogQuery): Condition[] => {
  const ce = tables.catalogEntries
  const conditions: Condition[] = []

  if (filters.search) {
    const pattern = `%${filters.search.toLowerCase()}%`
    conditions.push(
      sql`(
        lower(${ce.cveId}) LIKE ${pattern}
        OR lower(${ce.vendor}) LIKE ${pattern}
        OR lower(${ce.product}) LIKE ${pattern}
        OR lower(${ce.vulnerabilityName}) LIKE ${pattern}
        OR lower(${ce.description}) LIKE ${pattern}
        OR lower(${ce.aliases}) LIKE ${pattern}
      )`
    )
  }

  if (filters.source === 'kev') {
    conditions.push(eq(ce.hasSourceKev, 1))
  } else if (filters.source === 'enisa') {
    conditions.push(eq(ce.hasSourceEnisa, 1))
  } else if (filters.source === 'historic') {
    conditions.push(eq(ce.hasSourceHistoric, 1))
  } else if (filters.source === 'metasploit') {
    conditions.push(eq(ce.hasSourceMetasploit, 1))
  } else if (filters.source === 'poc') {
    conditions.push(eq(ce.hasSourcePoc, 1))
  }

  if (filters.publicExploitOnly) {
    conditions.push(sql`(${ce.hasSourceMetasploit} = 1 OR ${ce.hasSourcePoc} = 1)`)
  }

  if (filters.internetExposedOnly) {
    conditions.push(eq(ce.internetExposed, 1))
  }

  const vendorKeys = filters.vendorKeys ?? (filters.vendor ? [filters.vendor] : [])
  if (vendorKeys.length) {
    conditions.push(inArray(ce.vendorKey, vendorKeys))
  }

  const productKeys = filters.productKeys ?? (filters.product ? [filters.product] : [])
  if (productKeys.length) {
    conditions.push(inArray(ce.productKey, productKeys))
  }

  const dimensionCondition = (dimension: string, value: string) =>
    sql`exists (
      select 1
      from catalog_entry_dimensions d
      where d.cve_id = ${ce.cveId}
        and d.dimension = ${dimension}
        and d.value = ${value}
    )`

  if (filters.domain) {
    conditions.push(dimensionCondition('domain', filters.domain))
  }

  if (filters.exploit) {
    conditions.push(dimensionCondition('exploit', filters.exploit))
  }

  if (filters.vulnerability) {
    conditions.push(dimensionCondition('vulnerability', filters.vulnerability))
  }

  if (filters.ransomwareOnly) {
    conditions.push(eq(ce.hasKnownRansomware, 1))
  }

  if (filters.wellKnownOnly) {
    conditions.push(eq(ce.isWellKnown, 1))
  }

  if (typeof filters.startYear === 'number' && typeof filters.endYear === 'number') {
    conditions.push(
      sql`(${ce.dateAddedYear} IS NULL OR (${ce.dateAddedYear} >= ${filters.startYear} AND ${ce.dateAddedYear} <= ${filters.endYear}))`
    )
  }

  const addTimestampCondition = (
    column: typeof ce.dateAddedTs,
    comparison: 'gte' | 'lte',
    value?: string
  ) => {
    if (!value) {
      return
    }
    const timestamp = toTimestamp(value)
    if (timestamp === null) {
      return
    }
    if (comparison === 'gte') {
      conditions.push(sql`${column} IS NOT NULL AND ${column} >= ${timestamp}`)
    } else {
      conditions.push(sql`${column} IS NOT NULL AND ${column} <= ${timestamp}`)
    }
  }

  addTimestampCondition(ce.dateAddedTs, 'gte', filters.fromDate)
  addTimestampCondition(ce.dateAddedTs, 'lte', filters.toDate)
  addTimestampCondition(ce.dateUpdatedTs, 'gte', filters.fromUpdatedDate)
  addTimestampCondition(ce.dateUpdatedTs, 'lte', filters.toUpdatedDate)

  if (filters.cvssMin !== undefined) {
    conditions.push(sql`${ce.cvssScore} IS NOT NULL AND ${ce.cvssScore} >= ${filters.cvssMin}`)
  }

  if (filters.cvssMax !== undefined) {
    conditions.push(sql`${ce.cvssScore} IS NOT NULL AND ${ce.cvssScore} <= ${filters.cvssMax}`)
  }

  if (filters.epssMin !== undefined) {
    conditions.push(sql`${ce.epssScore} IS NOT NULL AND ${ce.epssScore} >= ${filters.epssMin}`)
  }

  if (filters.epssMax !== undefined) {
    conditions.push(sql`${ce.epssScore} IS NOT NULL AND ${ce.epssScore} <= ${filters.epssMax}`)
  }

  if (filters.priceMin !== undefined) {
    conditions.push(
      sql`exists (
        select 1
        from market_offer_targets target
        inner join market_offers offer on offer.id = target.offer_id
        where target.product_key = ${ce.productKey}
          and coalesce(offer.max_reward_usd, offer.min_reward_usd) >= ${filters.priceMin}
      )`
    )
  }

  if (filters.priceMax !== undefined) {
    conditions.push(
      sql`exists (
        select 1
        from market_offer_targets target
        inner join market_offers offer on offer.id = target.offer_id
        where target.product_key = ${ce.productKey}
          and coalesce(offer.min_reward_usd, offer.max_reward_usd) <= ${filters.priceMax}
      )`
    )
  }

  if (filters.marketProgramType) {
    conditions.push(
      sql`exists (
        select 1
        from market_offer_targets target
        inner join market_offers offer on offer.id = target.offer_id
        inner join market_programs program on program.id = offer.program_id
        where target.product_key = ${ce.productKey}
          and program.program_type = ${filters.marketProgramType}
      )`
    )
  }

  return conditions
}

const combineConditions = (conditions: Condition[]): Condition | undefined => {
  if (!conditions.length) {
    return undefined
  }

  if (conditions.length === 1) {
    return conditions[0]
  }

  return and(...(conditions as [Condition, Condition, ...Condition[]]))
}

const queryEntries = (
  db: DrizzleDatabase,
  filters: CatalogQuery,
  limitOverride?: number
): KevEntrySummary[] => {
  const ce = tables.catalogEntries
  const conditions = buildConditions(filters)
  const whereCondition = combineConditions(conditions)
  const limit = Math.max(
    1,
    Math.min(MAX_ENTRY_LIMIT, limitOverride ?? filters.limit ?? DEFAULT_ENTRY_LIMIT)
  )

  let query = db
    .select({
      cve_id: ce.cveId,
      entry_id: ce.entryId,
      sources: ce.sources,
      vendor: ce.vendor,
      vendor_key: ce.vendorKey,
      product: ce.product,
      product_key: ce.productKey,
      vulnerability_name: ce.vulnerabilityName,
      description: ce.description,
      due_date: ce.dueDate,
      date_added: ce.dateAdded,
      date_published: ce.datePublished,
      poc_published_at: ce.pocPublishedAt,
      ransomware_use: ce.ransomwareUse,
      cvss_score: ce.cvssScore,
      cvss_severity: ce.cvssSeverity,
      epss_score: ce.epssScore,
      aliases: ce.aliases,
      domain_categories: ce.domainCategories,
      exploit_layers: ce.exploitLayers,
      vulnerability_categories: ce.vulnerabilityCategories,
      internet_exposed: ce.internetExposed
    })
    .from(ce)

  if (whereCondition) {
    query = query.where(whereCondition)
  }

  const rows = query
    .orderBy(sql`${ce.dateAddedTs} IS NULL`, desc(ce.dateAddedTs), asc(ce.cveId))
    .limit(limit)
    .all() as CatalogSummaryRow[]

  const productKeys = Array.from(
    new Set(rows.map(row => row.product_key).filter((key): key is string => typeof key === 'string' && key.length > 0))
  )
  const marketSignals = getMarketSignalsForProducts(
    db,
    productKeys,
    filters.marketProgramType
      ? { programTypes: [filters.marketProgramType] }
      : undefined
  )

  return rows.map(row => catalogRowToSummary(row, { marketSignals }))
}

const queryDimensionCounts = (
  db: DrizzleDatabase,
  filters: CatalogQuery,
  dimension: 'domain' | 'exploit' | 'vulnerability'
): KevCountDatum[] => {
  const ce = tables.catalogEntries
  const conditions = buildConditions(filters)
  const whereCondition = combineConditions(conditions)

  let filteredBase = db.select({ cveId: ce.cveId }).from(ce)
  if (whereCondition) {
    filteredBase = filteredBase.where(whereCondition)
  }

  const filtered = db.$with('filtered_entries').as(filteredBase)
  const dim = alias(tables.catalogEntryDimensions, 'dim')
  const countExpr = sql<number>`count(*)`

  const rows = db
    .with(filtered)
    .select({
      key: dim.value,
      name: dim.name,
      count: countExpr
    })
    .from(dim)
    .innerJoin(filtered, eq(filtered.cveId, dim.cveId))
    .where(eq(dim.dimension, dimension))
    .groupBy(dim.value, dim.name)
    .orderBy(sql`count(*) DESC`, asc(dim.name))
    .all()

  return rows.map(row => ({ key: row.key, name: row.name, count: Number(row.count) }))
}

const TOP_COUNT_LIMIT = 15

const queryVendorCounts = (
  db: DrizzleDatabase,
  filters: CatalogQuery
): KevCountDatum[] => {
  const ce = tables.catalogEntries
  const conditions = buildConditions(filters)
  const whereCondition = combineConditions(conditions)

  let filteredBase = db.select({ vendorKey: ce.vendorKey, vendor: ce.vendor }).from(ce)
  if (whereCondition) {
    filteredBase = filteredBase.where(whereCondition)
  }

  const filtered = db.$with('filtered_vendors').as(filteredBase)
  const countExpr = sql<number>`count(*)`

  const rows = db
    .with(filtered)
    .select({
      key: filtered.vendorKey,
      name: sql<string>`max(${filtered.vendor})`,
      count: countExpr
    })
    .from(filtered)
    .where(ne(filtered.vendorKey, ''))
    .groupBy(filtered.vendorKey)
    .having(sql`max(${filtered.vendor}) != 'Other'`)
    .orderBy(sql`count(*) DESC`, sql`max(${filtered.vendor}) ASC`)
    .limit(TOP_COUNT_LIMIT)
    .all()

  return rows.map(row => ({
    key: row.key,
    name: row.name ?? row.key,
    count: Number(row.count)
  }))
}

const queryProductCounts = (
  db: DrizzleDatabase,
  filters: CatalogQuery
): KevCountDatum[] => {
  const ce = tables.catalogEntries
  const conditions = buildConditions(filters)
  const whereCondition = combineConditions(conditions)

  let filteredBase = db
    .select({
      productKey: ce.productKey,
      product: ce.product,
      vendorKey: ce.vendorKey,
      vendor: ce.vendor
    })
    .from(ce)
  if (whereCondition) {
    filteredBase = filteredBase.where(whereCondition)
  }

  const filtered = db.$with('filtered_products').as(filteredBase)
  const countExpr = sql<number>`count(*)`

  const rows = db
    .with(filtered)
    .select({
      key: filtered.productKey,
      name: sql<string>`max(${filtered.product})`,
      vendorKey: sql<string>`max(${filtered.vendorKey})`,
      vendorName: sql<string>`max(${filtered.vendor})`,
      count: countExpr
    })
    .from(filtered)
    .where(ne(filtered.productKey, ''))
    .groupBy(filtered.productKey)
    .having(sql`max(${filtered.product}) != 'Other'`)
    .orderBy(sql`count(*) DESC`, sql`max(${filtered.product}) ASC`)
    .limit(TOP_COUNT_LIMIT)
    .all()

  return rows.map(row => ({
    key: row.key,
    name: row.name ?? row.key,
    count: Number(row.count),
    vendorKey: row.vendorKey ?? '',
    vendorName: row.vendorName ?? ''
  }))
}

const countEntries = (db: DrizzleDatabase, filters: CatalogQuery): number => {
  const ce = tables.catalogEntries
  const conditions = buildConditions(filters)
  const whereCondition = combineConditions(conditions)
  const countExpr = sql<number>`count(*)`

  let query = db.select({ count: countExpr }).from(ce)
  if (whereCondition) {
    query = query.where(whereCondition)
  }

  const row = query.get()
  return row?.count ? Number(row.count) : 0
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

  const ce = tables.catalogEntries
  const row = db
    .select({
      earliest: sql<string | null>`min(${ce.dateAdded})`,
      latest: sql<string | null>`max(${ce.dateAdded})`
    })
    .from(ce)
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

  const ce = tables.catalogEntries
  const row = db
    .select({
      latest: sql<string | null>`max(coalesce(${ce.dateUpdated}, ${ce.dateAdded}))`
    })
    .from(ce)
    .get()

  return row?.latest ?? ''
}

const formatProgramTypeLabel = (value: string | null | undefined): string => {
  if (value === 'exploit-broker') {
    return 'Exploit brokers'
  }
  if (value === 'bug-bounty') {
    return 'Bug bounty'
  }
  return value ? value.replace(/-/g, ' ') : 'Other'
}

const normaliseReward = (value: number | null | undefined): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null
  }
  return value
}

const createEmptyMarketOverview = (): KevResponse['market'] => ({
  priceBounds: { minRewardUsd: null, maxRewardUsd: null },
  filteredPriceBounds: { minRewardUsd: null, maxRewardUsd: null },
  offerCount: 0,
  programCounts: [],
  categoryCounts: []
})

const computeMarketOverview = (
  db: DrizzleDatabase,
  productKeys: string[],
  options?: { programType?: MarketProgramType }
): KevResponse['market'] => {
  const offer = tables.marketOffers
  const target = tables.marketOfferTargets
  const program = tables.marketPrograms
  const category = tables.marketOfferCategories

  const globalBoundsRow = db
    .select({
      minRewardUsd: sql<number | null>`min(COALESCE(${offer.minRewardUsd}, ${offer.maxRewardUsd}))`,
      maxRewardUsd: sql<number | null>`max(COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd}))`
    })
    .from(offer)
    .innerJoin(target, eq(target.offerId, offer.id))
    .get()

  const uniqueKeys = Array.from(new Set(productKeys.filter(key => Boolean(key))))

  const programTypeFilter =
    options?.programType === 'exploit-broker' ||
    options?.programType === 'bug-bounty' ||
    options?.programType === 'other'
      ? options.programType
      : null

  if (!uniqueKeys.length) {
    return {
      ...createEmptyMarketOverview(),
      priceBounds: {
        minRewardUsd: normaliseReward(globalBoundsRow?.minRewardUsd ?? null),
        maxRewardUsd: normaliseReward(globalBoundsRow?.maxRewardUsd ?? null)
      }
    }
  }

  const productCondition = inArray(target.productKey, uniqueKeys)
  const programCondition =
    programTypeFilter !== null ? eq(program.programType, programTypeFilter) : null
  const combinedCondition = programCondition
    ? and(productCondition, programCondition)
    : productCondition

  const filteredRow = db
    .select({
      count: sql<number>`count(distinct ${offer.id})`,
      minRewardUsd: sql<number | null>`min(COALESCE(${offer.minRewardUsd}, ${offer.maxRewardUsd}))`,
      maxRewardUsd: sql<number | null>`max(COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd}))`
    })
    .from(target)
    .innerJoin(offer, eq(offer.id, target.offerId))
    .innerJoin(program, eq(program.id, offer.programId))
    .where(combinedCondition)
    .get()

  const programCountRows = db
    .select({
      programType: program.programType,
      count: sql<number>`count(distinct ${offer.id})`
    })
    .from(target)
    .innerJoin(offer, eq(offer.id, target.offerId))
    .innerJoin(program, eq(program.id, offer.programId))
    .where(combinedCondition)
    .groupBy(program.programType)
    .all()

  const programCounts = programCountRows
    .map(row => ({
      key: row.programType ?? 'other',
      name: formatProgramTypeLabel(row.programType),
      count: Number(row.count ?? 0)
    }))
    .sort((first, second) => second.count - first.count)

  const categoryRows = db
    .select({
      categoryType: category.categoryType,
      categoryKey: category.categoryKey,
      categoryName: category.categoryName,
      count: sql<number>`count(distinct ${offer.id})`
    })
    .from(target)
    .innerJoin(offer, eq(offer.id, target.offerId))
    .innerJoin(category, eq(category.offerId, offer.id))
    .innerJoin(program, eq(program.id, offer.programId))
    .where(combinedCondition)
    .groupBy(
      category.categoryType,
      category.categoryKey,
      category.categoryName
    )
    .all()

  const categoryCounts = categoryRows
    .map(row => ({
      key: row.categoryKey,
      name: row.categoryName,
      categoryType: row.categoryType,
      count: Number(row.count ?? 0)
    }))
    .sort((first, second) => second.count - first.count)

  return {
    priceBounds: {
      minRewardUsd: normaliseReward(globalBoundsRow?.minRewardUsd ?? null),
      maxRewardUsd: normaliseReward(globalBoundsRow?.maxRewardUsd ?? null)
    },
    filteredPriceBounds: {
      minRewardUsd: normaliseReward(filteredRow?.minRewardUsd ?? null),
      maxRewardUsd: normaliseReward(filteredRow?.maxRewardUsd ?? null)
    },
    offerCount: filteredRow?.count ? Number(filteredRow.count) : 0,
    programCounts,
    categoryCounts
  }
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
      totalEntriesWithoutYear: 0,
      entryLimit,
      market: createEmptyMarketOverview()
    }
  }

  const entries = queryEntries(db, filters, entryLimit)
  const totalEntries = countEntries(db, filters)
  const hasYearFilter = typeof filters.startYear === 'number' || typeof filters.endYear === 'number'
  const totalEntriesWithoutYear = hasYearFilter
    ? countEntries(db, omitFilters(filters, ['startYear', 'endYear']))
    : totalEntries

  const counts = {
    domain: queryDimensionCounts(
      db,
      omitFilters(filters, ['domain']),
      'domain'
    ),
    exploit: queryDimensionCounts(
      db,
      omitFilters(filters, ['exploit']),
      'exploit'
    ),
    vulnerability: queryDimensionCounts(
      db,
      omitFilters(filters, ['vulnerability']),
      'vulnerability'
    ),
    vendor: queryVendorCounts(
      db,
      omitFilters(filters, ['vendor', 'vendorKeys'])
    ),
    product: queryProductCounts(
      db,
      omitFilters(filters, ['product', 'productKeys'])
    )
  }

  const catalogBounds = getCatalogBounds(db)
  const updatedAt = computeUpdatedAt(db)
  const market = computeMarketOverview(
    db,
    entries
      .map(entry => entry.productKey)
      .filter((key): key is string => typeof key === 'string' && key.length > 0),
    filters.marketProgramType ? { programType: filters.marketProgramType } : undefined
  )

  return {
    updatedAt,
    entries,
    counts,
    catalogBounds,
    totalEntries,
    totalEntriesWithoutYear,
    entryLimit,
    market
  }
})
