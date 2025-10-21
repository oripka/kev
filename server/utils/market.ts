import { sql } from 'drizzle-orm'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'
import { setMetadata } from './sqlite'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'

type ImportMarketSummary = {
  imported: number
  offerCount: number
  programCount: number
  productCount: number
  lastCaptureAt: string | null
  lastSnapshotAt: string | null
}

const toCount = (value: unknown): number =>
  typeof value === 'number' && Number.isFinite(value) ? value : 0

export const importMarketIntel = async (db: DrizzleDatabase): Promise<ImportMarketSummary> => {
  try {
    markTaskRunning('market', 'Refreshing market intelligence metadata')
    setImportPhase('fetchingMarket', {
      message: 'Gathering latest market intelligence metrics',
      completed: 0,
      total: 0
    })
    markTaskProgress('market', 0, 0, 'Gathering latest market intelligence metrics')

    const offer = tables.marketOffers
    const program = tables.marketPrograms
    const target = tables.marketOfferTargets
    const snapshot = tables.marketProgramSnapshots

    const offerStats =
      db
        .select({
          offerCount: sql<number>`count(*)`,
          lastCaptureAt: sql<string | null>`max(${offer.sourceCaptureDate})`
        })
        .from(offer)
        .get() ?? null

    const programStats =
      db
        .select({ programCount: sql<number>`count(distinct ${program.id})` })
        .from(program)
        .get() ?? null

    const productStats =
      db
        .select({ productCount: sql<number>`count(distinct ${target.productKey})` })
        .from(target)
        .get() ?? null

    const snapshotStats =
      db
        .select({ lastSnapshotAt: sql<string | null>`max(${snapshot.fetchedAt})` })
        .from(snapshot)
        .get() ?? null

    const offerCount = toCount(offerStats?.offerCount)
    const programCount = toCount(programStats?.programCount)
    const productCount = toCount(productStats?.productCount)
    const lastCaptureAt = offerStats?.lastCaptureAt ?? null
    const lastSnapshotAt = snapshotStats?.lastSnapshotAt ?? null

    setImportPhase('savingMarket', {
      message: 'Recording market intelligence summary',
      completed: 0,
      total: 0
    })
    markTaskProgress('market', 0, 0, 'Recording market intelligence summary')

    const importedAt = new Date().toISOString()

    const metadataEntries: Array<[string, string]> = [
      ['market.lastImportAt', importedAt],
      ['market.offerCount', String(offerCount)],
      ['market.programCount', String(programCount)],
      ['market.productCount', String(productCount)]
    ]

    if (lastCaptureAt) {
      metadataEntries.push(['market.lastCaptureAt', lastCaptureAt])
    }

    if (lastSnapshotAt) {
      metadataEntries.push(['market.cachedAt', lastSnapshotAt])
    }

    for (const [key, value] of metadataEntries) {
      setMetadata(key, value)
    }

    const completionLabel =
      offerCount > 0
        ? `${offerCount.toLocaleString()} market offers summarised`
        : 'No market offers found in cache'

    markTaskComplete('market', completionLabel)

    return {
      imported: offerCount,
      offerCount,
      programCount,
      productCount,
      lastCaptureAt,
      lastSnapshotAt
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Market intelligence import failed'
    markTaskError('market', message)
    throw error
  }
}

