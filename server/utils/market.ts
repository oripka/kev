import { sql } from 'drizzle-orm'
import { tables, type DrizzleDatabase } from '../database/client'
import { runMarketImport } from '../market/importer'
import { marketPrograms } from '../market/programs'
import { setMetadataValue } from './metadata'
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

export const importMarketIntel = async (
  db: DrizzleDatabase,
  options: { forceRefresh?: boolean; allowStale?: boolean } = {}
): Promise<ImportMarketSummary> => {
  try {
    markTaskRunning('market', 'Refreshing market intelligence metadata')
    const totalPrograms = marketPrograms.length
    setImportPhase('fetchingMarket', {
      message: 'Fetching market intelligence sources',
      completed: 0,
      total: totalPrograms
    })
    markTaskProgress('market', 0, totalPrograms, 'Fetching market intelligence sources')

    let completedPrograms = 0
    const importResult = await runMarketImport(db, {
      forceRefresh: options.forceRefresh,
      allowStale: options.allowStale,
      onProgramStart: ({ program, index, total }) => {
        markTaskProgress('market', index, total, `Fetching ${program.name}`)
      },
      onProgramComplete: ({ program, total, offersProcessed }) => {
        completedPrograms += 1
        const label = offersProcessed
          ? `${program.name}: ${offersProcessed.toLocaleString()} offers processed`
          : `${program.name}: No offers found`
        markTaskProgress('market', completedPrograms, total, label)
      },
      onProgramError: ({ program, total, error }) => {
        completedPrograms += 1
        const message = error instanceof Error ? error.message : 'Import failed'
        console.error('Market program import failed', program.slug, error)
        markTaskProgress('market', completedPrograms, total, `${program.name}: ${message}`)
      }
    })

    const offer = tables.marketOffers
    const program = tables.marketPrograms
    const target = tables.marketOfferTargets
    const snapshot = tables.marketProgramSnapshots

    const [offerStats, programStats, productStats, snapshotStats] = await Promise.all([
      db
        .select({
          offerCount: sql<number>`count(*)`,
          lastCaptureAt: sql<string | null>`max(${offer.sourceCaptureDate})`
        })
        .from(offer)
        .get(),
      db
        .select({ programCount: sql<number>`count(distinct ${program.id})` })
        .from(program)
        .get(),
      db
        .select({ productCount: sql<number>`count(distinct ${target.productKey})` })
        .from(target)
        .get(),
      db
        .select({ lastSnapshotAt: sql<string | null>`max(${snapshot.fetchedAt})` })
        .from(snapshot)
        .get()
    ])

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
    markTaskProgress('market', completedPrograms, totalPrograms, 'Recording market intelligence summary')

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

    await Promise.all(metadataEntries.map(([key, value]) => setMetadataValue(key, value)))

    const completionLabel =
      offerCount > 0
        ? `${offerCount.toLocaleString()} market offers summarised`
        : 'No market offers found in cache'

    markTaskComplete('market', completionLabel)

    return {
      imported: importResult.offersProcessed,
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

