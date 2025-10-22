import { getQuery } from 'h3'
import { and, asc, eq, inArray, or, sql, type SQL } from 'drizzle-orm'
import { alias } from 'drizzle-orm/sqlite-core'
import type {
  CvssSeverity,
  MarketOffersResponse,
  MarketOfferCategoryTag,
  MarketOfferTarget,
  MarketOfferTargetMatch,
  MarketOfferTargetMatchMethod,
  MarketProgramType
} from '~/types'
import { tables } from '../../database/client'
import { getDatabase } from '../../utils/sqlite'

type Condition = SQL<unknown>

const DEFAULT_PAGE_SIZE = 25
const MAX_PAGE_SIZE = 100

const normaliseReward = (value: unknown): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null
  }
  return value
}

const normaliseProgramType = (value: string | null | undefined): MarketProgramType => {
  if (value === 'exploit-broker' || value === 'bug-bounty') {
    return value
  }
  return 'other'
}

const parseJsonArray = <T>(value: string | null | undefined): T[] => {
  if (typeof value !== 'string' || !value.trim()) {
    return []
  }

  try {
    const parsed = JSON.parse(value)
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed.filter((item): item is T => item !== null && item !== undefined)
  } catch {
    return []
  }
}

const parseBooleanParam = (value: unknown): boolean | null => {
  if (typeof value === 'boolean') {
    return value
  }
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase()
    if (trimmed === 'true') {
      return true
    }
    if (trimmed === 'false') {
      return false
    }
  }
  return null
}

const parseNumberParam = (value: unknown): number | null => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number.parseFloat(value.trim())
    if (!Number.isNaN(parsed) && Number.isFinite(parsed)) {
      return parsed
    }
  }
  return null
}

const parseIntParam = (value: unknown): number | null => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value)
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number.parseInt(value.trim(), 10)
    if (!Number.isNaN(parsed) && Number.isFinite(parsed)) {
      return parsed
    }
  }
  return null
}

const parseListParam = (value: unknown): string[] => {
  if (typeof value === 'string') {
    return value
      .split(',')
      .map(item => item.trim())
      .filter(Boolean)
  }

  if (Array.isArray(value)) {
    return value
      .map(item => (typeof item === 'string' ? item.trim() : ''))
      .filter(Boolean)
  }

  return []
}

const clampConfidence = (value: unknown): number | null => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.min(100, Math.max(0, Math.round(value)))
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number.parseFloat(value.trim())
    if (!Number.isNaN(parsed) && Number.isFinite(parsed)) {
      return Math.min(100, Math.max(0, Math.round(parsed)))
    }
  }

  return null
}

const normaliseMatchMethod = (value: unknown): MarketOfferTargetMatchMethod => {
  if (typeof value !== 'string') {
    return 'unknown'
  }

  const normalised = value.trim().toLowerCase()

  if (normalised === 'exact' || normalised === 'fuzzy' || normalised === 'manual-review') {
    return normalised
  }

  return 'unknown'
}

const parseStringArrayField = (value: unknown): string[] => {
  if (typeof value !== 'string' || !value.trim()) {
    return []
  }

  try {
    const parsed = JSON.parse(value)
    if (Array.isArray(parsed)) {
      return parsed
        .map(entry => (typeof entry === 'string' ? entry.trim() : ''))
        .filter(Boolean)
    }
  } catch {
    // ignore parse errors and fall through to empty array
  }

  return []
}

const normaliseCvssSeverity = (value: unknown): CvssSeverity | null => {
  if (typeof value !== 'string') {
    return null
  }

  const normalised = value.trim().toLowerCase()

  switch (normalised) {
    case 'none':
      return 'None'
    case 'low':
      return 'Low'
    case 'medium':
      return 'Medium'
    case 'high':
      return 'High'
    case 'critical':
      return 'Critical'
    default:
      return null
  }
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

type SortKey = 'sourceCaptureDate' | 'maxRewardUsd' | 'minRewardUsd' | 'averageRewardUsd' | 'title' | 'programName'

const isSortKey = (value: string): value is SortKey =>
  value === 'sourceCaptureDate' ||
  value === 'maxRewardUsd' ||
  value === 'minRewardUsd' ||
  value === 'averageRewardUsd' ||
  value === 'title' ||
  value === 'programName'

type OfferRow = {
  id: string
  title: string
  description: string | null
  programName: string
  programType: string | null
  minRewardUsd: number | null
  maxRewardUsd: number | null
  sourceUrl: string
  sourceCaptureDate: string
  exclusivity: string | null
  targetData: string | null
  categoryData: string | null
  targetCveIds: string | null
  kevMatchIds: string | null
}

type CatalogEntryRow = {
  cveId: string
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
  vulnerabilityName: string
  domainCategories: string | null
  exploitLayers: string | null
  vulnerabilityCategories: string | null
  cvssScore: number | null
  cvssSeverity: string | null
  cvssVector: string | null
}

type TargetEntryRow = {
  productKey?: string
  productName?: string
  vendorKey?: string
  vendorName?: string
  cveId?: string | null
  confidence?: number | string | null
  matchMethod?: string | null
}

export default defineEventHandler(async event => {
  const query = getQuery(event)

  const searchTerm = typeof query.q === 'string' ? query.q.trim().toLowerCase() : ''
  const programTypes = parseListParam(query.programType).map(type => normaliseProgramType(type))
  const hasKevOnly = parseBooleanParam(query.hasKev) ?? false

  let minReward = parseNumberParam(query.minReward)
  let maxReward = parseNumberParam(query.maxReward)

  if (minReward !== null && maxReward !== null && minReward > maxReward) {
    const temp = minReward
    minReward = maxReward
    maxReward = temp
  }

  const sortParam = typeof query.sort === 'string' ? query.sort : ''
  const sortKey: SortKey = isSortKey(sortParam) ? sortParam : 'sourceCaptureDate'

  const directionParam = typeof query.direction === 'string' ? query.direction.toLowerCase() : ''
  const sortDirection: 'asc' | 'desc' = directionParam === 'asc' ? 'asc' : 'desc'

  const requestedPage = Math.max(parseIntParam(query.page) ?? 1, 1)
  const pageSize = Math.max(
    1,
    Math.min(parseIntParam(query.pageSize) ?? DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE)
  )

  const db = getDatabase()
  const offer = tables.marketOffers
  const program = tables.marketPrograms
  const target = tables.marketOfferTargets
  const product = tables.productCatalog
  const category = tables.marketOfferCategories
  const catalog = tables.catalogEntries

  const conditions: Condition[] = []

  if (searchTerm) {
    const pattern = `%${searchTerm}%`
    conditions.push(
      sql`(
        lower(${offer.title}) like ${pattern}
        or lower(${offer.description}) like ${pattern}
        or lower(${program.name}) like ${pattern}
        or lower(${program.operator}) like ${pattern}
        or lower(${product.productName}) like ${pattern}
        or lower(${product.vendorName}) like ${pattern}
      )`
    )
  }

  const uniqueProgramTypes = Array.from(new Set(programTypes))
  if (uniqueProgramTypes.length && uniqueProgramTypes.length < 3) {
    const subConditions: Condition[] = []

    if (uniqueProgramTypes.includes('exploit-broker')) {
      subConditions.push(eq(program.programType, 'exploit-broker'))
    }

    if (uniqueProgramTypes.includes('bug-bounty')) {
      subConditions.push(eq(program.programType, 'bug-bounty'))
    }

    if (uniqueProgramTypes.includes('other')) {
      subConditions.push(
        sql`(
          ${program.programType} IS NULL
          OR ${program.programType} NOT IN ('exploit-broker', 'bug-bounty')
        )`
      )
    }

    if (subConditions.length === 1) {
      conditions.push(subConditions[0])
    } else if (subConditions.length > 1) {
      conditions.push(or(...(subConditions as [Condition, Condition, ...Condition[]])))
    }
  }

  if (minReward !== null) {
    conditions.push(
      sql`coalesce(${offer.maxRewardUsd}, ${offer.minRewardUsd}) >= ${minReward}`
    )
  }

  if (maxReward !== null) {
    conditions.push(
      sql`coalesce(${offer.minRewardUsd}, ${offer.maxRewardUsd}) <= ${maxReward}`
    )
  }

  if (hasKevOnly) {
    conditions.push(
      sql`exists (
        select 1
        from market_offer_targets kev_target
        inner join catalog_entries kev_catalog on kev_catalog.product_key = kev_target.product_key
        where kev_target.offer_id = ${offer.id}
      )`
    )
  }

  const whereCondition = combineConditions(conditions)

  let countQuery = db
    .select({ value: sql<number>`count(distinct ${offer.id})` })
    .from(offer)
    .innerJoin(program, eq(program.id, offer.programId))
    .leftJoin(target, eq(target.offerId, offer.id))
    .leftJoin(product, eq(product.productKey, target.productKey))

  if (whereCondition) {
    countQuery = countQuery.where(whereCondition)
  }

  const total = countQuery.get()?.value ?? 0
  const maxPage = total > 0 ? Math.max(1, Math.ceil(total / pageSize)) : 1
  const page = Math.min(requestedPage, maxPage)
  const offset = (page - 1) * pageSize

  const kevEntry = alias(catalog, 'kev_entry')

  const targetSelect = sql<string | null>`json_group_array(distinct json_object(
    'productKey', ${product.productKey},
    'productName', ${product.productName},
    'vendorKey', ${product.vendorKey},
    'vendorName', ${product.vendorName},
    'cveId', ${target.cveId},
    'confidence', ${target.confidence},
    'matchMethod', ${target.matchMethod}
  ))`

  const categorySelect = sql<string | null>`json_group_array(distinct json_object(
    'type', ${category.categoryType},
    'key', ${category.categoryKey},
    'name', ${category.categoryName}
  ))`

  const targetCveSelect = sql<string | null>`json_group_array(distinct ${target.cveId})`
  const kevCveSelect = sql<string | null>`json_group_array(distinct ${kevEntry.cveId})`

  let dataQuery = db
    .select({
      id: offer.id,
      title: offer.title,
      description: offer.description,
      programName: program.name,
      programType: program.programType,
      minRewardUsd: offer.minRewardUsd,
      maxRewardUsd: offer.maxRewardUsd,
      sourceUrl: offer.sourceUrl,
      sourceCaptureDate: offer.sourceCaptureDate,
      exclusivity: offer.exclusivity,
      targetData: targetSelect,
      categoryData: categorySelect,
      targetCveIds: targetCveSelect,
      kevMatchIds: kevCveSelect
    })
    .from(offer)
    .innerJoin(program, eq(program.id, offer.programId))
    .leftJoin(target, eq(target.offerId, offer.id))
    .leftJoin(product, eq(product.productKey, target.productKey))
    .leftJoin(category, eq(category.offerId, offer.id))
    .leftJoin(kevEntry, eq(kevEntry.productKey, product.productKey))

  if (whereCondition) {
    dataQuery = dataQuery.where(whereCondition)
  }

  const sortExpressionMap: Record<SortKey, SQL> = {
    sourceCaptureDate: sql`${offer.sourceCaptureDate}`,
    maxRewardUsd: sql`coalesce(${offer.maxRewardUsd}, ${offer.minRewardUsd})`,
    minRewardUsd: sql`coalesce(${offer.minRewardUsd}, ${offer.maxRewardUsd})`,
    averageRewardUsd: sql`(
      coalesce(${offer.minRewardUsd}, ${offer.maxRewardUsd}) +
      coalesce(${offer.maxRewardUsd}, ${offer.minRewardUsd})
    ) / 2.0`,
    title: sql`${offer.title}`,
    programName: sql`${program.name}`
  }

  const primaryOrder = sortDirection === 'asc'
    ? sql`${sortExpressionMap[sortKey]} ASC`
    : sql`${sortExpressionMap[sortKey]} DESC`

  dataQuery = dataQuery
    .groupBy(
      offer.id,
      offer.title,
      offer.description,
      offer.minRewardUsd,
      offer.maxRewardUsd,
      offer.sourceUrl,
      offer.sourceCaptureDate,
      offer.exclusivity,
      program.name,
      program.programType
    )
    .orderBy(primaryOrder, asc(offer.id))
    .limit(pageSize)
    .offset(offset)

  const rows = dataQuery.all() as OfferRow[]

  type IntermediateOffer = {
    id: string
    title: string
    description: string | null
    programName: string
    programType: MarketProgramType
    minRewardUsd: number | null
    maxRewardUsd: number | null
    averageRewardUsd: number | null
    sourceUrl: string
    sourceCaptureDate: string
    exclusivity: string | null
    targets: MarketOfferTarget[]
    categories: MarketOfferCategoryTag[]
    matchedCveIds: string[]
    matchedKevCveIds: string[]
  }

  const matchedCveAccumulator = new Set<string>()

  const intermediateItems = rows.map<IntermediateOffer>(row => {
    const minRewardValue = normaliseReward(row.minRewardUsd)
    const maxRewardValue = normaliseReward(row.maxRewardUsd)

    const averageReward =
      minRewardValue !== null || maxRewardValue !== null
        ? ((minRewardValue ?? maxRewardValue ?? 0) + (maxRewardValue ?? minRewardValue ?? 0)) / 2
        : null

    const parsedTargets = parseJsonArray<Partial<TargetEntryRow>>(row.targetData)
    const targets: MarketOfferTarget[] = []

    for (const targetEntry of parsedTargets) {
      const productKey = typeof targetEntry.productKey === 'string' ? targetEntry.productKey : ''
      const productName = typeof targetEntry.productName === 'string' ? targetEntry.productName : ''
      const vendorKey = typeof targetEntry.vendorKey === 'string' ? targetEntry.vendorKey : ''
      const vendorName = typeof targetEntry.vendorName === 'string' ? targetEntry.vendorName : ''

      if (!productKey || !productName || !vendorKey || !vendorName) {
        continue
      }

      const cveId = typeof targetEntry.cveId === 'string' && targetEntry.cveId.trim()
        ? targetEntry.cveId.trim()
        : null

      if (cveId) {
        matchedCveAccumulator.add(cveId)
      }

      const confidence = clampConfidence(targetEntry.confidence ?? null)
      const matchMethod = normaliseMatchMethod(targetEntry.matchMethod)

      targets.push({
        productKey,
        productName,
        vendorKey,
        vendorName,
        cveId,
        confidence,
        matchMethod,
        matches: []
      })
    }

    const parsedCategories = parseJsonArray<Partial<MarketOfferCategoryTag>>(row.categoryData)
    const categories: MarketOfferCategoryTag[] = []

    for (const categoryEntry of parsedCategories) {
      const type = typeof categoryEntry.type === 'string' ? categoryEntry.type : ''
      const key = typeof categoryEntry.key === 'string' ? categoryEntry.key : ''
      const name = typeof categoryEntry.name === 'string' ? categoryEntry.name : ''

      if (!type || !key || !name) {
        continue
      }

      const exists = categories.some(
        existing => existing.type === type && existing.key === key
      )

      if (!exists) {
        categories.push({ type, key, name })
      }
    }

    const directCves = parseJsonArray<string | null>(row.targetCveIds)
      .map(value => (typeof value === 'string' ? value.trim() : ''))
      .filter(Boolean)

    const kevCves = parseJsonArray<string | null>(row.kevMatchIds)
      .map(value => (typeof value === 'string' ? value.trim() : ''))
      .filter(Boolean)

    const matchedKevCveIds = Array.from(new Set(kevCves))
    const matchedCveIds = Array.from(new Set([...directCves, ...matchedKevCveIds]))

    for (const cveId of matchedCveIds) {
      matchedCveAccumulator.add(cveId)
    }

    return {
      id: row.id,
      title: row.title,
      description: row.description,
      programName: row.programName,
      programType: normaliseProgramType(row.programType),
      minRewardUsd: minRewardValue,
      maxRewardUsd: maxRewardValue,
      averageRewardUsd: averageReward,
      sourceUrl: row.sourceUrl,
      sourceCaptureDate: row.sourceCaptureDate,
      exclusivity: row.exclusivity,
      targets,
      categories,
      matchedCveIds,
      matchedKevCveIds
    }
  })

  const catalogMatchesByCveId = new Map<string, MarketOfferTargetMatch>()
  const catalogMatchesByProductKey = new Map<string, MarketOfferTargetMatch[]>()

  if (matchedCveAccumulator.size) {
    const catalogRows = db
      .select({
        cveId: catalog.cveId,
        productKey: catalog.productKey,
        productName: catalog.product,
        vendorKey: catalog.vendorKey,
        vendorName: catalog.vendor,
        vulnerabilityName: catalog.vulnerabilityName,
        domainCategories: catalog.domainCategories,
        exploitLayers: catalog.exploitLayers,
        vulnerabilityCategories: catalog.vulnerabilityCategories,
        cvssScore: catalog.cvssScore,
        cvssSeverity: catalog.cvssSeverity,
        cvssVector: catalog.cvssVector
      })
      .from(catalog)
      .where(inArray(catalog.cveId, Array.from(matchedCveAccumulator)))
      .all() as CatalogEntryRow[]

    for (const entry of catalogRows) {
      const domainCategories = parseStringArrayField(entry.domainCategories) as MarketOfferTargetMatch['domainCategories']
      const exploitLayers = parseStringArrayField(entry.exploitLayers) as MarketOfferTargetMatch['exploitLayers']
      const vulnerabilityCategories = parseStringArrayField(entry.vulnerabilityCategories) as MarketOfferTargetMatch['vulnerabilityCategories']

      const cvssScoreValue =
        typeof entry.cvssScore === 'number' && Number.isFinite(entry.cvssScore)
          ? entry.cvssScore
          : null

      const cvssVectorValue =
        typeof entry.cvssVector === 'string' && entry.cvssVector.trim()
          ? entry.cvssVector.trim()
          : null

      const match: MarketOfferTargetMatch = {
        cveId: entry.cveId,
        vulnerabilityName: entry.vulnerabilityName,
        vendorName: entry.vendorName,
        vendorKey: entry.vendorKey,
        productName: entry.productName,
        productKey: entry.productKey,
        domainCategories,
        exploitLayers,
        vulnerabilityCategories,
        cvssScore: cvssScoreValue,
        cvssSeverity: normaliseCvssSeverity(entry.cvssSeverity),
        cvssVector: cvssVectorValue
      }

      catalogMatchesByCveId.set(match.cveId, match)

      const existing = catalogMatchesByProductKey.get(match.productKey)
      if (existing) {
        if (!existing.some(candidate => candidate.cveId === match.cveId)) {
          existing.push(match)
        }
      } else {
        catalogMatchesByProductKey.set(match.productKey, [match])
      }
    }
  }

  const items = intermediateItems.map<MarketOffersResponse['items'][number]>(item => {
    const enrichedTargets = item.targets.map(target => {
      const matches: MarketOfferTargetMatch[] = []

      if (target.cveId) {
        const directMatch = catalogMatchesByCveId.get(target.cveId)
        if (directMatch) {
          matches.push(directMatch)
        }
      }

      const relatedMatches = catalogMatchesByProductKey.get(target.productKey) ?? []
      for (const candidate of relatedMatches) {
        if (!matches.some(existing => existing.cveId === candidate.cveId)) {
          matches.push(candidate)
        }
      }

      return { ...target, matches }
    })

    return {
      id: item.id,
      title: item.title,
      description: item.description,
      programName: item.programName,
      programType: item.programType,
      minRewardUsd: item.minRewardUsd,
      maxRewardUsd: item.maxRewardUsd,
      averageRewardUsd: item.averageRewardUsd,
      sourceUrl: item.sourceUrl,
      sourceCaptureDate: item.sourceCaptureDate,
      exclusivity: item.exclusivity,
      targets: enrichedTargets,
      categories: item.categories,
      matchedCveIds: item.matchedCveIds,
      matchedKevCveIds: item.matchedKevCveIds
    }
  })

  const response: MarketOffersResponse = {
    items,
    total,
    page,
    pageSize
  }

  return response
})
