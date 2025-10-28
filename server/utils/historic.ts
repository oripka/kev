import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { eq, inArray } from 'drizzle-orm'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from '../database/client'
import { setMetadataValue } from './metadata'
import {
  buildEntryDiffRecords,
  diffEntryRecords,
  insertCategoryRecords,
  insertImpactRecords,
  loadExistingEntryRecords,
  persistEntryRecord
} from './entry-diff'
import type { ImportStrategy } from './import-types'
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

type HistoricImportSummary = {
  imported: number
  totalCount: number
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: ImportStrategy
}

export const importHistoricCatalog = async (
  db: DrizzleDatabase,
  options: { strategy?: ImportStrategy } = {}
): Promise<HistoricImportSummary> => {
  const strategy = options.strategy ?? 'full'
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

    const enrichedEntries = cvelistResults.map(result => enrichEntry(result.entry))
    const entryRecords = buildEntryDiffRecords(
      enrichedEntries,
      'historic',
      impactRecordMap
    )
    const totalEntries = entryRecords.length
    const useIncremental = strategy === 'incremental'

    if (!useIncremental) {
      setImportPhase('savingHistoric', {
        message: 'Saving historic entries to the local cache',
        completed: 0,
        total: totalEntries
      })
      markTaskProgress(
        'historic',
        0,
        totalEntries,
        'Saving historic entries to the local cache'
      )

      await db
        .delete(tables.vulnerabilityEntries)
        .where(eq(tables.vulnerabilityEntries.source, 'historic'))
        .run()

      for (let index = 0; index < entryRecords.length; index += 1) {
        const record = entryRecords[index]

        await db.insert(tables.vulnerabilityEntries).values(record.values).run()

        if (record.impacts.length) {
          await insertImpactRecords(db, record.impacts)
        }

        if (record.categories.length) {
          await insertCategoryRecords(db, record.categories)
        }

        if ((index + 1) % 25 === 0 || index + 1 === entryRecords.length) {
          const message = `Saving historic entries to the local cache (${index + 1} of ${entryRecords.length})`
          setImportPhase('savingHistoric', {
            message,
            completed: index + 1,
            total: entryRecords.length
          })
          markTaskProgress('historic', index + 1, entryRecords.length, message)
        }
      }

      const importedAt = new Date().toISOString()
      await Promise.all([
        setMetadataValue('historic.lastImportAt', importedAt),
        setMetadataValue('historic.totalCount', String(totalEntries)),
        setMetadataValue('historic.lastNewCount', String(totalEntries)),
        setMetadataValue('historic.lastUpdatedCount', '0'),
        setMetadataValue('historic.lastSkippedCount', '0'),
        setMetadataValue('historic.lastRemovedCount', '0'),
        setMetadataValue('historic.lastImportStrategy', 'full')
      ])

      markTaskComplete(
        'historic',
        `${totalEntries.toLocaleString()} historic entries cached`
      )

      return {
        imported: totalEntries,
        totalCount: totalEntries,
        newCount: totalEntries,
        updatedCount: 0,
        skippedCount: 0,
        removedCount: 0,
        strategy: 'full'
      }
    }

    const existingMap = await loadExistingEntryRecords(db, 'historic')
    const { newRecords, updatedRecords, unchangedRecords, removedIds } =
      diffEntryRecords(entryRecords, existingMap)
    const totalChanges = newRecords.length + updatedRecords.length

    if (totalChanges > 0) {
      const message = 'Saving historic changes to the local cache'
      setImportPhase('savingHistoric', {
        message,
        completed: 0,
        total: totalChanges
      })
      markTaskProgress('historic', 0, totalChanges, message)
    } else if (removedIds.length > 0) {
      const message = `Removing ${removedIds.length.toLocaleString()} retired historic entr${removedIds.length === 1 ? 'y' : 'ies'}`
      setImportPhase('savingHistoric', {
        message,
        completed: 0,
        total: 0
      })
      markTaskProgress('historic', 0, 0, message)
    } else {
      const message = 'Historic catalog already up to date'
      setImportPhase('savingHistoric', {
        message,
        completed: 0,
        total: 0
      })
      markTaskProgress('historic', 0, 0, message)
    }

    let processed = 0
    for (const record of newRecords) {
      await persistEntryRecord(db, record, 'insert')
      if (totalChanges > 0) {
        const completed = processed + 1
        const progressMessage = `Saving historic changes to the local cache (${completed} of ${totalChanges})`
        setImportPhase('savingHistoric', {
          message: progressMessage,
          completed,
          total: totalChanges
        })
        markTaskProgress('historic', completed, totalChanges, progressMessage)
      }
      processed += 1
    }
    for (const record of updatedRecords) {
      await persistEntryRecord(db, record, 'update')
      if (totalChanges > 0) {
        const completed = processed + 1
        const progressMessage = `Saving historic changes to the local cache (${completed} of ${totalChanges})`
        setImportPhase('savingHistoric', {
          message: progressMessage,
          completed,
          total: totalChanges
        })
        markTaskProgress('historic', completed, totalChanges, progressMessage)
      }
      processed += 1
    }

    if (removedIds.length > 0) {
      const chunkSize = 25
      for (let index = 0; index < removedIds.length; index += chunkSize) {
        const idChunk = removedIds.slice(index, index + chunkSize)
        await db
          .delete(tables.vulnerabilityEntries)
          .where(inArray(tables.vulnerabilityEntries.id, idChunk))
          .run()
      }
    }

    const importedAt = new Date().toISOString()
    await Promise.all([
      setMetadataValue('historic.lastImportAt', importedAt),
      setMetadataValue('historic.totalCount', String(totalEntries)),
      setMetadataValue('historic.lastNewCount', String(newRecords.length)),
      setMetadataValue('historic.lastUpdatedCount', String(updatedRecords.length)),
      setMetadataValue('historic.lastSkippedCount', String(unchangedRecords.length)),
      setMetadataValue('historic.lastRemovedCount', String(removedIds.length)),
      setMetadataValue('historic.lastImportStrategy', 'incremental')
    ])

    const changeSegments: string[] = []
    if (newRecords.length > 0) {
      changeSegments.push(`${newRecords.length.toLocaleString()} new`)
    }
    if (updatedRecords.length > 0) {
      changeSegments.push(`${updatedRecords.length.toLocaleString()} updated`)
    }
    if (removedIds.length > 0) {
      changeSegments.push(`${removedIds.length.toLocaleString()} removed`)
    }

    const summaryLabel = changeSegments.length
      ? `Historic catalog updated (${changeSegments.join(', ')})`
      : 'Historic catalog already up to date'

    markTaskComplete('historic', summaryLabel)

    return {
      imported: totalChanges,
      totalCount: totalEntries,
      newCount: newRecords.length,
      updatedCount: updatedRecords.length,
      skippedCount: unchangedRecords.length,
      removedCount: removedIds.length,
      strategy: 'incremental'
    }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : typeof error === 'string' ? error : 'Historic import failed'
    markTaskError('historic', message)
    throw error instanceof Error ? error : new Error(message)
  }
}
