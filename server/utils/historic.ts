import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import type { DrizzleDatabase } from './sqlite'
import { setMetadata } from './sqlite'
import {
  CVELIST_ENRICHMENT_CONCURRENCY,
  enrichBaseEntryWithCvelist,
  flushCvelistCache,
  type VulnerabilityImpactRecord
} from './cvelist'
import { mapWithConcurrency } from './concurrency'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'
import {
  createEntryRecords,
  saveEntryRecords,
  type ImportStrategy
} from './importDiff'

const historicEntrySchema = z.object({
  cve: z.string(),
  title: z.string(),
  year: z.number().int().min(1970).max(2100).optional(),
  product: z.string().optional(),
  vendor: z.string().optional(),
  context: z.string().optional(),
  notes: z.string().optional()
})

const historicDatasetSchema = z.array(historicEntrySchema)

const toIsoDate = (year?: number): string => {
  if (typeof year !== 'number' || !Number.isFinite(year)) {
    return ''
  }

  const clampedYear = Math.min(2100, Math.max(1970, Math.trunc(year)))
  return new Date(Date.UTC(clampedYear, 0, 1)).toISOString()
}

const toNotes = (context?: string, notes?: string): string[] => {
  const entries = [context, notes]
    .map(value => value?.trim())
    .filter((value): value is string => Boolean(value))

  return Array.from(new Set(entries))
}

const toBaseEntry = (item: z.infer<typeof historicEntrySchema>): KevBaseEntry | null => {
  const cveId = item.cve?.trim()
  if (!cveId) {
    return null
  }

  const normalised = normaliseVendorProduct(
    { vendor: item.vendor, product: item.product },
    undefined,
    undefined,
    {
      vulnerabilityName: item.title,
      description: item.context ?? item.notes ?? undefined,
      cveId
    }
  )
  const dateAdded = toIsoDate(item.year)
  const notes = toNotes(item.context, item.notes)

  return {
    id: `historic:${cveId.toUpperCase()}`,
    sources: ['historic'],
    cveId: cveId.toUpperCase(),
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    affectedProducts: [],
    problemTypes: [],
    vulnerabilityName: item.title?.trim() || cveId.toUpperCase(),
    description: item.context?.trim() || item.notes?.trim() || '',
    requiredAction: null,
    dateAdded,
    dueDate: null,
    ransomwareUse: null,
    notes,
    cwes: [],
    cvssScore: null,
    cvssVector: null,
    cvssVersion: null,
    cvssSeverity: null,
    epssScore: null,
    assigner: null,
    datePublished: dateAdded || null,
    dateUpdated: null,
    exploitedSince: dateAdded || null,
    sourceUrl: null,
    pocUrl: null,
    pocPublishedAt: null,
    references: [],
    aliases: [cveId.toUpperCase()],
    metasploitModulePath: null,
    metasploitModulePublishedAt: null,
    internetExposed: false
  }
}

type ImportHistoricOptions = {
  strategy?: ImportStrategy
}

type ImportHistoricSummary = {
  imported: number
  total: number
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: ImportStrategy
}

export const importHistoricCatalog = async (
  db: DrizzleDatabase,
  options: ImportHistoricOptions = {}
): Promise<ImportHistoricSummary> => {
  markTaskRunning('historic', 'Loading historic exploit dataset')

  try {
    setImportPhase('fetchingHistoric', {
      message: 'Loading historic exploit dataset',
      completed: 0,
      total: 0
    })
    markTaskProgress('historic', 0, 0, 'Loading historic exploit dataset')

    const datasetPath = join(process.cwd(), 'historic.json')

    const rawContents = await readFile(datasetPath, 'utf8').catch(error => {
      throw new Error(`Unable to read historic dataset: ${(error as Error).message}`)
    })

    const parsedJson = (() => {
      try {
        return JSON.parse(rawContents)
      } catch (error) {
        throw new Error(`Unable to parse historic dataset: ${(error as Error).message}`)
      }
    })()

    const parsed = historicDatasetSchema.safeParse(parsedJson)

    if (!parsed.success) {
      throw new Error('Historic dataset has an invalid format')
    }

    const baseEntries = parsed.data
      .map(toBaseEntry)
      .filter((entry): entry is KevBaseEntry => entry !== null)

    const cvelistResults = await mapWithConcurrency(
      baseEntries,
      CVELIST_ENRICHMENT_CONCURRENCY,
      async base => {
        try {
          return await enrichBaseEntryWithCvelist(base)
        } catch {
          return { entry: base, impacts: [], hit: false }
        }
      }
    )

    await flushCvelistCache()

    let cvelistHits = 0
    let cvelistMisses = 0
    for (const result of cvelistResults) {
      if (result.hit) {
        cvelistHits += 1
      } else {
        cvelistMisses += 1
      }
    }

    if (cvelistHits > 0 || cvelistMisses > 0) {
      const message = `Historic CVEList enrichment (${cvelistHits} hits, ${cvelistMisses} misses)`
      markTaskProgress('historic', 0, 0, message)
    }

    const impactRecordMap = new Map<string, VulnerabilityImpactRecord[]>()
    for (const result of cvelistResults) {
      if (result.impacts.length) {
        impactRecordMap.set(result.entry.id, result.impacts)
      }
    }

    const entries = cvelistResults.map(result => enrichEntry(result.entry))
    const strategy: ImportStrategy = options.strategy === 'incremental' ? 'incremental' : 'full'
    const entryRecords = createEntryRecords(entries, 'historic', impactRecordMap)

    const saveResult = saveEntryRecords({
      db,
      source: 'historic',
      records: entryRecords,
      strategy,
      callbacks: {
        onFullStart(total) {
          setImportPhase('savingHistoric', {
            message: 'Saving historic entries to the local cache',
            completed: 0,
            total
          })
          markTaskProgress('historic', 0, total, 'Saving historic entries to the local cache')
        },
        onFullProgress(index, total) {
          if ((index + 1) % 25 !== 0 && index + 1 !== total) {
            return
          }
          const completed = index + 1
          const message = `Saving historic entries to the local cache (${completed} of ${total})`
          setImportPhase('savingHistoric', { message, completed, total })
          markTaskProgress('historic', completed, total, message)
        },
        onIncrementalStart({ totalChanges, removedCount }) {
          if (totalChanges > 0) {
            const message = 'Saving historic changes to the local cache'
            setImportPhase('savingHistoric', { message, completed: 0, total: totalChanges })
            markTaskProgress('historic', 0, totalChanges, message)
          } else if (removedCount > 0) {
            const message = `Removing ${removedCount.toLocaleString()} retired historic entr${removedCount === 1 ? 'y' : 'ies'}`
            setImportPhase('savingHistoric', { message, completed: 0, total: 0 })
            markTaskProgress('historic', 0, 0, message)
          } else {
            const message = 'Historic dataset already up to date'
            setImportPhase('savingHistoric', { message, completed: 0, total: 0 })
            markTaskProgress('historic', 0, 0, message)
          }
        },
        onIncrementalProgress(processed, totalChanges) {
          const message = `Saving historic changes to the local cache (${processed} of ${totalChanges})`
          setImportPhase('savingHistoric', { message, completed: processed, total: totalChanges })
          markTaskProgress('historic', processed, totalChanges, message)
        }
      }
    })

    const importedAt = new Date().toISOString()
    setMetadata('historic.lastImportAt', importedAt)
    setMetadata('historic.totalCount', String(entries.length))
    setMetadata('historic.lastNewCount', String(saveResult.newCount))
    setMetadata('historic.lastUpdatedCount', String(saveResult.updatedCount))
    setMetadata('historic.lastSkippedCount', String(saveResult.skippedCount))
    setMetadata('historic.lastRemovedCount', String(saveResult.removedCount))
    setMetadata('historic.lastImportStrategy', strategy)

    if (strategy === 'incremental') {
      const detailSegments: string[] = []
      if (saveResult.newCount > 0) {
        detailSegments.push(`${saveResult.newCount.toLocaleString()} new`)
      }
      if (saveResult.updatedCount > 0) {
        detailSegments.push(`${saveResult.updatedCount.toLocaleString()} updated`)
      }
      if (saveResult.skippedCount > 0) {
        detailSegments.push(`${saveResult.skippedCount.toLocaleString()} unchanged`)
      }
      if (saveResult.removedCount > 0) {
        detailSegments.push(`${saveResult.removedCount.toLocaleString()} removed`)
      }
      const detailSummary = detailSegments.length
        ? detailSegments.join(', ')
        : 'no changes detected'
      markTaskComplete(
        'historic',
        `Incremental historic import: ${detailSummary} (catalog size: ${entries.length.toLocaleString()})`
      )
    } else {
      markTaskComplete('historic', `${entries.length.toLocaleString()} historic entries cached`)
    }

    return {
      imported: saveResult.newCount + saveResult.updatedCount,
      total: entries.length,
      newCount: saveResult.newCount,
      updatedCount: saveResult.updatedCount,
      skippedCount: saveResult.skippedCount,
      removedCount: saveResult.removedCount,
      strategy
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : typeof error === 'string' ? error : 'Historic import failed'
    markTaskError('historic', message)
    throw error instanceof Error ? error : new Error(message)
  }
}
