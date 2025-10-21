import { getQuery } from 'h3'
import { and, asc, eq, or, sql, type SQL } from 'drizzle-orm'
import { alias } from 'drizzle-orm/sqlite-core'
import type {
  MarketOffersResponse,
  MarketOfferCategoryTag,
  MarketOfferTarget,
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

  const kevTarget = alias(target, 'kev_target')
  const kevCatalog = alias(catalog, 'kev_catalog')

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
        from ${kevTarget}
        inner join ${kevCatalog} on ${kevCatalog.productKey} = ${kevTarget.productKey}
        where ${kevTarget.offerId} = ${offer.id}
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
    'cveId', ${target.cveId}
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

  const items = rows.map<MarketOffersResponse['items'][number]>(row => {
    const minRewardValue = normaliseReward(row.minRewardUsd)
    const maxRewardValue = normaliseReward(row.maxRewardUsd)

    const averageReward =
      minRewardValue !== null || maxRewardValue !== null
        ? ((minRewardValue ?? maxRewardValue ?? 0) + (maxRewardValue ?? minRewardValue ?? 0)) / 2
        : null

    const parsedTargets = parseJsonArray<Partial<MarketOfferTarget>>(row.targetData)
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

      targets.push({
        productKey,
        productName,
        vendorKey,
        vendorName,
        cveId
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

  const response: MarketOffersResponse = {
    items,
    total,
    page,
    pageSize
  }

  return response
})
