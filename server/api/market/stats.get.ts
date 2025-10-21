import { defineEventHandler } from 'h3'
import { eq, sql } from 'drizzle-orm'
import { tables } from '../../database/client'
import { getDatabase } from '../../utils/sqlite'
import type { MarketStatsResponse } from '~/types'

const normaliseReward = (value: number | null | undefined): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null
  }
  return value
}

const normaliseProgramType = (value: string | null | undefined): string => {
  if (value === 'exploit-broker' || value === 'bug-bounty') {
    return value
  }
  return value ?? 'other'
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

const createDefaultStats = (): MarketStatsResponse => ({
  totals: {
    offerCount: 0,
    programCount: 0,
    averageRewardUsd: null,
    minRewardUsd: null,
    maxRewardUsd: null,
    lastSeenAt: null
  },
  programCounts: [],
  categoryCounts: [],
  topOffers: []
})

export default defineEventHandler((): MarketStatsResponse => {
  const db = getDatabase()
  const offer = tables.marketOffers
  const target = tables.marketOfferTargets
  const program = tables.marketPrograms
  const category = tables.marketOfferCategories
  const productCatalog = tables.productCatalog

  const totalsRow = db
    .select({
      offerCount: sql<number>`count(distinct ${offer.id})`,
      programCount: sql<number>`count(distinct ${offer.programId})`,
      minRewardUsd: sql<number | null>`min(COALESCE(${offer.minRewardUsd}, ${offer.maxRewardUsd}))`,
      maxRewardUsd: sql<number | null>`max(COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd}))`,
      averageRewardUsd: sql<number | null>`avg((COALESCE(${offer.minRewardUsd}, ${offer.maxRewardUsd}) + COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd})) / 2.0)`,
      lastSeenAt: sql<string | null>`max(${offer.sourceCaptureDate})`
    })
    .from(offer)
    .get()

  const programCountRows = db
    .select({
      programType: program.programType,
      count: sql<number>`count(distinct ${offer.id})`
    })
    .from(offer)
    .innerJoin(program, eq(program.id, offer.programId))
    .groupBy(program.programType)
    .all()

  const programCounts = programCountRows
    .map(row => ({
      key: normaliseProgramType(row.programType),
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
    .from(offer)
    .innerJoin(category, eq(category.offerId, offer.id))
    .groupBy(category.categoryType, category.categoryKey, category.categoryName)
    .all()

  const categoryCounts = categoryRows
    .map(row => ({
      key: row.categoryKey,
      name: row.categoryName,
      categoryType: row.categoryType,
      count: Number(row.count ?? 0)
    }))
    .sort((first, second) => second.count - first.count)

  const topOfferRows = db
    .select({
      id: offer.id,
      title: offer.title,
      minRewardUsd: offer.minRewardUsd,
      maxRewardUsd: offer.maxRewardUsd,
      sourceUrl: offer.sourceUrl,
      sourceCaptureDate: offer.sourceCaptureDate,
      programName: program.name,
      programType: program.programType,
      productNames: sql<string | null>`group_concat(distinct ${productCatalog.productName})`,
      vendorNames: sql<string | null>`group_concat(distinct ${productCatalog.vendorName})`,
      targetSummaries: sql<string | null>`group_concat(distinct ${productCatalog.vendorName} || ' · ' || ${productCatalog.productName})`
    })
    .from(offer)
    .innerJoin(program, eq(program.id, offer.programId))
    .leftJoin(target, eq(target.offerId, offer.id))
    .leftJoin(productCatalog, eq(productCatalog.productKey, target.productKey))
    .groupBy(offer.id)
    .orderBy(sql`max(COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd})) DESC`)
    .limit(10)
    .all()

  const topOffers = topOfferRows.map(row => {
    const minReward = normaliseReward(row.minRewardUsd)
    const maxReward = normaliseReward(row.maxRewardUsd)
    const averageReward =
      minReward !== null || maxReward !== null
        ? ((minReward ?? maxReward ?? 0) + (maxReward ?? minReward ?? 0)) / 2
        : null

    const splitValues = (value: string | null | undefined) =>
      value
        ? value
            .split(',')
            .map(entry => entry.trim())
            .filter(Boolean)
        : []

    return {
      id: row.id,
      title: row.title,
      programName: row.programName,
      programType: normaliseProgramType(row.programType),
      minRewardUsd: minReward,
      maxRewardUsd: maxReward,
      averageRewardUsd: averageReward,
      sourceUrl: row.sourceUrl,
      sourceCaptureDate: row.sourceCaptureDate,
      productNames: splitValues(row.productNames),
      vendorNames: splitValues(row.vendorNames),
      targetSummaries: splitValues(row.targetSummaries)
    }
  })

  if (!totalsRow) {
    return createDefaultStats()
  }

  return {
    totals: {
      offerCount: Number(totalsRow.offerCount ?? 0),
      programCount: Number(totalsRow.programCount ?? 0),
      averageRewardUsd: normaliseReward(totalsRow.averageRewardUsd ?? null),
      minRewardUsd: normaliseReward(totalsRow.minRewardUsd ?? null),
      maxRewardUsd: normaliseReward(totalsRow.maxRewardUsd ?? null),
      lastSeenAt: totalsRow.lastSeenAt ?? null
    },
    programCounts,
    categoryCounts,
    topOffers
  }
})
