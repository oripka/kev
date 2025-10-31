import { createHash, randomUUID } from 'node:crypto'
import { and, eq } from 'drizzle-orm'
import type { CatalogSource } from '~/types'
import { matchExploitProduct } from '~/utils/exploitProductHints'
import { matchVendorProductByTitle } from '../utils/metasploitVendorCatalog'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from '../database/client'
import {
  computeValuationScore,
  convertAmountToUsd,
  createOfferTermsHash,
  fetchUsdExchangeRates
} from './utils'
import { marketPrograms } from './programs'
import type {
  MarketOfferInput,
  MarketProgramDefinition,
  MarketProgramProgress,
  MarketProgramSnapshot
} from './types'
import { getCachedData } from '../utils/cache'
import { publishTaskEvent } from '../utils/import-progress'

type ExchangeRates = Awaited<ReturnType<typeof fetchUsdExchangeRates>>

type ProductCatalogRecord = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
  sources: Set<CatalogSource>
}

type NormalisedTarget = {
  productKey: string
  vendorName: string
  productName: string
  cveId: string | null
  confidence: number
  matchMethod: 'exact' | 'fuzzy' | 'manual-review'
}

const cveProductCache = new Map<string, { vendor: string; product: string } | null>()

const normaliseCveId = (value: string | null | undefined): string | null => {
  if (typeof value !== 'string') {
    return null
  }

  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  return trimmed.toUpperCase()
}

const normaliseInputLabel = (value: string | null | undefined): string | null => {
  if (typeof value !== 'string') {
    return null
  }

  const trimmed = value.trim()
  return trimmed.length ? trimmed : null
}

const lookupProductForCve = async (db: DrizzleDatabase, cveId: string | null | undefined) => {
  const normalised = normaliseCveId(cveId)
  if (!normalised) {
    return null
  }

  if (cveProductCache.has(normalised)) {
    return cveProductCache.get(normalised) ?? null
  }

  const row = await db
    .select({
      vendor: tables.vulnerabilityEntries.vendor,
      product: tables.vulnerabilityEntries.product
    })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.cveId, normalised))
    .get()

  let result: { vendor: string; product: string } | null = null
  if (row?.vendor && row?.product) {
    const normalisedVendorProduct = normaliseVendorProduct({
      vendor: row.vendor,
      product: row.product
    })
    result = {
      vendor: normalisedVendorProduct.vendor.label,
      product: normalisedVendorProduct.product.label
    }
  }
  cveProductCache.set(normalised, result)
  return result
}

const EXCHANGE_RATES_TTL_MS = 43_200_000
// Cache market program snapshots for one week to avoid redundant refreshes.
const SNAPSHOT_TTL_MS = 7 * 24 * 60 * 60 * 1000

type ImportOptions = {
  onProgramStart?: (info: { program: MarketProgramDefinition; index: number; total: number }) => void
  onProgramComplete?: (info: {
    program: MarketProgramDefinition
    index: number
    total: number
    offersProcessed: number
  }) => void
  onProgramError?: (info: { program: MarketProgramDefinition; index: number; total: number; error: unknown }) => void
}

export type MarketImportOptions = ImportOptions & {
  forceRefresh?: boolean
  allowStale?: boolean
}

const parseSources = (value: string | null | undefined): CatalogSource[] => {
  if (!value) {
    return []
  }
  try {
    const parsed = JSON.parse(value) as unknown
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is CatalogSource => typeof item === 'string')
    }
  } catch {}
  return []
}

const loadProductCatalog = async (db: DrizzleDatabase): Promise<Map<string, ProductCatalogRecord>> => {
  const rows = await db
    .select({
      productKey: tables.productCatalog.productKey,
      productName: tables.productCatalog.productName,
      vendorKey: tables.productCatalog.vendorKey,
      vendorName: tables.productCatalog.vendorName,
      sources: tables.productCatalog.sources
    })
    .from(tables.productCatalog)
    .all()

  const catalog = new Map<string, ProductCatalogRecord>()
  for (const row of rows) {
    const sources = new Set(parseSources(row.sources))
    catalog.set(row.productKey, {
      productKey: row.productKey,
      productName: row.productName,
      vendorKey: row.vendorKey,
      vendorName: row.vendorName,
      sources
    })
  }
  return catalog
}

const toSearchTerms = (vendorName: string, productName: string): string =>
  `${vendorName} ${productName}`.toLowerCase()

const ensureCatalogRecord = async (
  db: DrizzleDatabase,
  catalog: Map<string, ProductCatalogRecord>,
  source: CatalogSource,
  vendorLabel: string,
  productLabel: string
): ProductCatalogRecord => {
  const normalised = normaliseVendorProduct({ vendor: vendorLabel, product: productLabel })
  const productKey = normalised.product.key
  const vendorKey = normalised.vendor.key
  const vendorName = normalised.vendor.label
  const productName = normalised.product.label

  const existing = catalog.get(productKey)
  if (existing) {
    const sources = new Set(existing.sources)
    if (!sources.has(source)) {
      sources.add(source)
      await db
        .update(tables.productCatalog)
        .set({
          sources: JSON.stringify(Array.from(sources))
        })
        .where(eq(tables.productCatalog.productKey, productKey))
        .run()
      existing.sources = sources
    }

    let updated = false
    if (productName.length > existing.productName.length) {
      existing.productName = productName
      updated = true
    }
    if (vendorName.length > existing.vendorName.length) {
      existing.vendorName = vendorName
      updated = true
    }
    if (updated) {
      await db
        .update(tables.productCatalog)
        .set({
          productName: existing.productName,
          vendorName: existing.vendorName,
          searchTerms: toSearchTerms(existing.vendorName, existing.productName)
        })
        .where(eq(tables.productCatalog.productKey, productKey))
        .run()
    }
    return existing
  }

  const sources = new Set<CatalogSource>([source])
  await db
    .insert(tables.productCatalog)
    .values({
      productKey,
      productName,
      vendorKey,
      vendorName,
      sources: JSON.stringify(Array.from(sources)),
      searchTerms: toSearchTerms(vendorName, productName)
    })
    .run()

  const record: ProductCatalogRecord = {
    productKey,
    productName,
    vendorKey,
    vendorName,
    sources
  }
  catalog.set(productKey, record)
  return record
}

const prepareTargets = async (
  db: DrizzleDatabase,
  catalog: Map<string, ProductCatalogRecord>,
  program: MarketProgramDefinition,
  offer: MarketOfferInput
): Promise<NormalisedTarget[]> => {
  const results: NormalisedTarget[] = []
  const seen = new Set<string>()

  const offerLevelCveIds = new Set<string>()
  for (const raw of offer.cveIds ?? []) {
    const normalised = normaliseCveId(raw)
    if (normalised) {
      offerLevelCveIds.add(normalised)
    }
  }

  for (const target of offer.targets ?? []) {
    const candidateVendor = normaliseInputLabel(target.vendor)
    const candidateProduct = normaliseInputLabel(target.product)
    const fallbackProduct =
      candidateProduct ??
      normaliseInputLabel(target.rawText) ??
      normaliseInputLabel(offer.title) ??
      normaliseInputLabel(program.name) ??
      'Unknown target'

    if (!candidateProduct && !candidateVendor && !target.rawText && !offer.title) {
      continue
    }

    let resolvedVendor = candidateVendor
    let resolvedProduct = candidateProduct
    let matchedCveId: string | null = null

    const targetCveIds = new Set<string>(offerLevelCveIds)
    const targetSpecificCve = normaliseCveId(target.cveId)
    if (targetSpecificCve) {
      targetCveIds.add(targetSpecificCve)
    }

    if ((!resolvedVendor || !resolvedProduct) && targetCveIds.size) {
      for (const cveId of targetCveIds) {
        const match = await lookupProductForCve(db, cveId)
        if (match) {
          if (!resolvedVendor) {
            resolvedVendor = match.vendor
          }
          if (!resolvedProduct) {
            resolvedProduct = match.product
          }
          matchedCveId = cveId
          break
        }
      }
    }

    let catalogHint: ReturnType<typeof matchVendorProductByTitle> | null = null
    let hintMatch: ReturnType<typeof matchExploitProduct> | null = null
    if ((!resolvedVendor || !resolvedProduct) && (target.rawText || fallbackProduct)) {
      const contextSegments = [
        target.rawText,
        fallbackProduct,
        offer.title,
        program.name
      ].filter((value): value is string => typeof value === 'string' && value.length > 0)

      catalogHint = matchVendorProductByTitle(contextSegments)
      if (catalogHint) {
        if (!resolvedVendor) {
          resolvedVendor = catalogHint.vendor
        }
        if (!resolvedProduct) {
          resolvedProduct = catalogHint.product
        }
      }

      const contextForHints = contextSegments.join(' ') || target.rawText || fallbackProduct || ''
      hintMatch = matchExploitProduct(contextForHints)
      if (hintMatch) {
        if (!resolvedVendor) {
          resolvedVendor = hintMatch.vendor
        }
        if (!resolvedProduct) {
          resolvedProduct = hintMatch.product
        }
      }
    }

    if (!resolvedVendor) {
      resolvedVendor = program.operator || 'Unknown'
    }

    if (!resolvedProduct) {
      resolvedProduct = fallbackProduct
    }

    const record = await ensureCatalogRecord(
      db,
      catalog,
      'market',
      resolvedVendor,
      resolvedProduct
    )
    if (seen.has(record.productKey)) {
      continue
    }
    seen.add(record.productKey)

    const effectiveCveId = targetSpecificCve ?? matchedCveId
    const confidence =
      typeof target.confidence === 'number'
        ? target.confidence
        : matchedCveId
          ? 100
          : catalogHint
            ? 85
            : hintMatch
              ? 75
              : 50
    const matchMethod: NormalisedTarget['matchMethod'] = target.matchMethod
      ?? (matchedCveId
        ? 'exact'
        : catalogHint || hintMatch
          ? 'fuzzy'
          : candidateVendor || candidateProduct
            ? 'exact'
            : 'manual-review')

    results.push({
      productKey: record.productKey,
      vendorName: record.vendorName,
      productName: record.productName,
      cveId: effectiveCveId,
      confidence,
      matchMethod
    })
  }

  return results
}

const upsertProgram = async (
  db: DrizzleDatabase,
  program: MarketProgramDefinition
) => {
  const now = new Date().toISOString()
  await db
    .insert(tables.marketPrograms)
    .values({
      id: program.slug,
      slug: program.slug,
      name: program.name,
      operator: program.operator,
      programType: program.programType,
      homepageUrl: program.homepageUrl,
      scrapeFrequency: program.scrapeFrequency,
      description: program.description ?? null,
      updatedAt: now
    })
    .onConflictDoUpdate({
      target: tables.marketPrograms.slug,
      set: {
        name: program.name,
        operator: program.operator,
        programType: program.programType,
        homepageUrl: program.homepageUrl,
        scrapeFrequency: program.scrapeFrequency,
        description: program.description ?? null,
        updatedAt: now
      }
    })
    .run()
}

const recordSnapshot = async (
  db: DrizzleDatabase,
  programId: string,
  snapshot: MarketProgramSnapshot,
  parserVersion: string
) => {
  const hash = createHash('sha256').update(snapshot.raw).digest('hex')
  await db
    .insert(tables.marketProgramSnapshots)
    .values({
      id: randomUUID(),
      programId,
      fetchedAt: snapshot.fetchedAt,
      rawContent: snapshot.raw,
      parserVersion,
      contentHash: hash
    })
    .run()
}

const saveOffer = async (
  db: DrizzleDatabase,
  program: MarketProgramDefinition,
  snapshot: MarketProgramSnapshot,
  offer: MarketOfferInput,
  catalog: Map<string, ProductCatalogRecord>,
  rates: ExchangeRates
): Promise<string | null> => {
  const targets = await prepareTargets(db, catalog, program, offer)
  if (!targets.length) {
    return null
  }

  const minUsd = convertAmountToUsd(offer.minReward?.amount ?? null, offer.minReward?.currency ?? offer.currency, rates)
  const maxUsd = convertAmountToUsd(offer.maxReward?.amount ?? null, offer.maxReward?.currency ?? offer.currency, rates)
  const rewardType =
    offer.rewardType ?? (minUsd !== null && maxUsd !== null && minUsd !== maxUsd ? 'range' : 'flat')
  const captureDate = offer.sourceCaptureDate ?? snapshot.fetchedAt
  const categories = Array.from(
    new Map(
      (offer.categories ?? []).map(category => [
        `${category.type}:${category.key}`,
        { ...category }
      ])
    ).values()
  )

  const hashParts: string[] = [
    offer.title ?? '',
    offer.description ?? '',
    String(minUsd ?? ''),
    String(maxUsd ?? ''),
    offer.exclusivity ?? '',
    offer.sourceUrl ?? program.homepageUrl,
    rewardType
  ]
  if (offer.cveIds?.length) {
    hashParts.push(...[...offer.cveIds].sort())
  }
  if (categories.length) {
    hashParts.push(...categories.map(category => `${category.type}:${category.key}`).sort())
  }
  hashParts.push(...targets.map(target => target.productKey).sort())
  const termsHash = createOfferTermsHash(program.slug, hashParts)

  const existing = await db
    .select({ id: tables.marketOffers.id })
    .from(tables.marketOffers)
    .where(and(eq(tables.marketOffers.programId, program.slug), eq(tables.marketOffers.termsHash, termsHash)))
    .get()

  const now = new Date().toISOString()
  let offerId: string
  if (existing) {
    offerId = existing.id
    await db
      .update(tables.marketOffers)
      .set({
        title: offer.title,
        description: offer.description ?? null,
        minRewardUsd: minUsd,
        maxRewardUsd: maxUsd,
        currency: 'USD',
        rewardType,
        exclusivity: offer.exclusivity ?? null,
        sourceUrl: offer.sourceUrl ?? program.homepageUrl,
        sourceCaptureDate: captureDate,
        effectiveStart: offer.effectiveStart ?? null,
        effectiveEnd: offer.effectiveEnd ?? null,
        cveId: offer.cveIds?.[0] ?? null,
        updatedAt: now,
        termsHash
      })
      .where(eq(tables.marketOffers.id, offerId))
      .run()
  } else {
    offerId = randomUUID()
    await db
      .insert(tables.marketOffers)
      .values({
        id: offerId,
        programId: program.slug,
        title: offer.title,
        description: offer.description ?? null,
        minRewardUsd: minUsd,
        maxRewardUsd: maxUsd,
        currency: 'USD',
        rewardType,
        exclusivity: offer.exclusivity ?? null,
        sourceUrl: offer.sourceUrl ?? program.homepageUrl,
        sourceCaptureDate: captureDate,
        effectiveStart: offer.effectiveStart ?? null,
        effectiveEnd: offer.effectiveEnd ?? null,
        cveId: offer.cveIds?.[0] ?? null,
        termsHash,
        createdAt: now,
        updatedAt: now
      })
      .run()
  }

  await db
    .delete(tables.marketOfferTargets)
    .where(eq(tables.marketOfferTargets.offerId, offerId))
    .run()
  for (const target of targets) {
    await db
      .insert(tables.marketOfferTargets)
      .values({
        offerId,
        productKey: target.productKey,
        cveId: target.cveId,
        confidence: target.confidence,
        matchMethod: target.matchMethod
      })
      .run()
  }

  await db
    .delete(tables.marketOfferCategories)
    .where(eq(tables.marketOfferCategories.offerId, offerId))
    .run()
  for (const category of categories) {
    await db
      .insert(tables.marketOfferCategories)
      .values({
        offerId,
        categoryType: category.type,
        categoryKey: category.key,
        categoryName: category.name
      })
      .run()
  }

  const valuation = computeValuationScore({
    minRewardUsd: minUsd,
    maxRewardUsd: maxUsd,
    exclusivity: offer.exclusivity ?? null,
    sourceCaptureDate: captureDate
  })

  await db
    .delete(tables.marketOfferMetrics)
    .where(eq(tables.marketOfferMetrics.offerId, offerId))
    .run()
  await db
    .insert(tables.marketOfferMetrics)
    .values({
      id: randomUUID(),
      offerId,
      valuationScore: valuation.score,
      scoreBreakdown: JSON.stringify(valuation.breakdown),
      computedAt: now
    })
    .run()

  return offerId
}

const saveProgram = async (
  db: DrizzleDatabase,
  program: MarketProgramDefinition,
  snapshot: MarketProgramSnapshot,
  offers: MarketOfferInput[],
  catalog: Map<string, ProductCatalogRecord>,
  rates: ExchangeRates
): Promise<number> => {
  publishTaskEvent(
    'market',
    `${program.name}: saving snapshot (${offers.length.toLocaleString()} offers)`
  )
  await upsertProgram(db, program)
  await recordSnapshot(db, program.slug, snapshot, program.parserVersion)

  let processed = 0
  for (const offer of offers) {
    const result = await saveOffer(db, program, snapshot, offer, catalog, rates)
    if (result) {
      processed += 1
    }
  }
  publishTaskEvent(
    'market',
    `${program.name}: stored ${processed.toLocaleString()} offers in database`
  )
  return processed
}

export type MarketImportResult = {
  offersProcessed: number
  programsProcessed: number
  programSummaries: MarketProgramProgress[]
}

export const runMarketImport = async (
  db: DrizzleDatabase,
  options: MarketImportOptions = {}
): Promise<MarketImportResult> => {
  const {
    onProgramStart,
    onProgramComplete,
    onProgramError,
    forceRefresh = false,
    allowStale = false
  } = options

  const ratesResult = await getCachedData('market-exchange-rates', fetchUsdExchangeRates, {
    ttlMs: EXCHANGE_RATES_TTL_MS,
    forceRefresh,
    allowStale
  })
  const rates = ratesResult.data
  publishTaskEvent(
    'market',
    `Exchange rates ${ratesResult.cacheHit ? 'loaded from cache' : 'fetched from API'}${
      ratesResult.stale ? ' (stale)' : ''
    }`
  )

  const catalog = await loadProductCatalog(db)
  const programSummaries: MarketProgramProgress[] = []
  let offersProcessed = 0
  const totalPrograms = marketPrograms.length

  for (let index = 0; index < marketPrograms.length; index += 1) {
    const program = marketPrograms[index]
    onProgramStart?.({ program, index, total: totalPrograms })

    try {
      const snapshotResult = await getCachedData<MarketProgramSnapshot>(
        `market-program-${program.slug}`,
        program.fetchSnapshot,
        {
          ttlMs: SNAPSHOT_TTL_MS,
          forceRefresh,
          allowStale
        }
      )
      publishTaskEvent(
        'market',
        `${program.name}: snapshot ${
          snapshotResult.cacheHit ? 'cache hit' : 'fetched from source'
        }${snapshotResult.stale ? ' (stale)' : ''}`
      )
      const snapshot = snapshotResult.data
      const offers = await program.parseOffers(snapshot)
      publishTaskEvent(
        'market',
        `${program.name}: parsed ${offers.length.toLocaleString()} offers`
      )
      const processed = await saveProgram(db, program, snapshot, offers, catalog, rates)
      offersProcessed += processed
      programSummaries.push({ program, offersProcessed: processed })
      onProgramComplete?.({ program, index, total: totalPrograms, offersProcessed: processed })
    } catch (error) {
      onProgramError?.({ program, index, total: totalPrograms, error })
    }
  }

  return {
    offersProcessed,
    programsProcessed: programSummaries.length,
    programSummaries
  }
}
