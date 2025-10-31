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

const customEntrySchema = z.object({
  slug: z.string(),
  cve: z.string().optional(),
  title: z.string(),
  vendor: z.string().optional(),
  product: z.string().optional(),
  summary: z.string().optional(),
  description: z.string().optional(),
  notes: z.union([z.string(), z.array(z.string())]).optional(),
  references: z.array(z.string()).optional(),
  aliases: z.union([z.string(), z.array(z.string())]).optional(),
  source_url: z.string().optional(),
  date_disclosed: z.string().optional(),
  date_added: z.string().optional(),
  date_exploited: z.string().optional()
})

const customDatasetSchema = z.array(customEntrySchema)

const toSlug = (value: string): string => {
  const trimmed = value.trim()
  return trimmed
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

const isCveIdentifier = (value: string): boolean => /^CVE-\d{4}-\d{4,}$/i.test(value)

const toCustomCve = (slug: string): string => `CUSTOM-${slug.toUpperCase().replace(/[^A-Z0-9]+/g, '-')}`

const normaliseDate = (value?: string | null): string => {
  if (!value) {
    return ''
  }
  const trimmed = value.trim()
  if (!trimmed) {
    return ''
  }
  const isoPattern = /^\d{4}-\d{2}-\d{2}$/
  if (isoPattern.test(trimmed)) {
    const [year, month, day] = trimmed.split('-').map(part => Number.parseInt(part, 10))
    if (Number.isFinite(year) && Number.isFinite(month) && Number.isFinite(day)) {
      return new Date(Date.UTC(year, month - 1, day)).toISOString()
    }
  }
  const parsed = new Date(trimmed)
  if (Number.isNaN(parsed.getTime())) {
    return ''
  }
  return parsed.toISOString()
}

const toStringArray = (value?: string | string[] | null): string[] => {
  if (!value) {
    return []
  }
  if (Array.isArray(value)) {
    return value
      .map(entry => entry?.trim())
      .filter((entry): entry is string => Boolean(entry))
  }
  const trimmed = value.trim()
  return trimmed ? [trimmed] : []
}

const toReferenceList = (references?: string[] | null): string[] => {
  if (!references) {
    return []
  }
  const unique = new Set<string>()
  for (const reference of references) {
    const trimmed = reference?.trim()
    if (trimmed) {
      unique.add(trimmed)
    }
  }
  return Array.from(unique)
}

const toAliasList = (cveId: string, slug: string, additional: string[]): string[] => {
  const aliases = new Set<string>()
  if (cveId) {
    aliases.add(cveId.toUpperCase())
  }
  if (slug) {
    aliases.add(slug.toUpperCase().replace(/[^A-Z0-9]+/g, '-'))
  }
  for (const alias of additional) {
    const trimmed = alias.trim()
    if (trimmed) {
      aliases.add(trimmed)
    }
  }
  return Array.from(aliases)
}

const toBaseEntry = (item: z.infer<typeof customEntrySchema>): KevBaseEntry | null => {
  const rawSlug = item.slug?.trim()
  if (!rawSlug) {
    return null
  }

  const slug = toSlug(rawSlug)
  const rawCve = item.cve?.trim()
  const cveId = rawCve && isCveIdentifier(rawCve) ? rawCve.toUpperCase() : toCustomCve(slug)

  const normalised = normaliseVendorProduct(
    { vendor: item.vendor, product: item.product },
    undefined,
    undefined,
    {
      vulnerabilityName: item.title,
      description: item.description ?? item.summary ?? undefined,
      cveId
    }
  )

  const dateAdded = normaliseDate(item.date_added ?? item.date_disclosed)
  const exploitedSince = normaliseDate(item.date_exploited ?? item.date_disclosed ?? item.date_added)
  const description = item.description?.trim() ?? item.summary?.trim() ?? ''
  const notes = toStringArray(item.notes)
  const references = toReferenceList(item.references)
  const sourceUrl = item.source_url?.trim() || null
  const providedAliases = toStringArray(item.aliases)
  const aliases = toAliasList(cveId, slug, providedAliases)

  return {
    id: `custom:${slug}`,
    sources: ['custom'],
    cveId,
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    affectedProducts: [],
    problemTypes: [],
    vulnerabilityName: item.title?.trim() || aliases[0] || cveId,
    description,
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
    exploitedSince: exploitedSince || dateAdded || null,
    sourceUrl,
    pocUrl: null,
    pocPublishedAt: null,
    references,
    aliases,
    metasploitModulePath: null,
    metasploitModulePublishedAt: null,
    internetExposed: false
  }
}

const shouldEnrichWithCvelist = (entry: KevBaseEntry): boolean => isCveIdentifier(entry.cveId)

type CustomImportSummary = {
  imported: number
  totalCount: number
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: ImportStrategy
}

export const importCustomCatalog = async (
  db: DrizzleDatabase,
  options: { strategy?: ImportStrategy } = {}
): Promise<CustomImportSummary> => {
  const strategy = options.strategy ?? 'full'
  markTaskRunning('custom', 'Loading curated research feed')

  try {
    setImportPhase('fetchingCustom', {
      message: 'Loading curated research feed',
      completed: 0,
      total: 0
    })
    markTaskProgress('custom', 0, 0, 'Loading curated research feed')

    const datasetPath = join(process.cwd(), 'custom.json')

    const rawContents = await readFile(datasetPath, 'utf8').catch(error => {
      throw new Error(`Unable to read custom dataset: ${(error as Error).message}`)
    })

    const parsedJson = (() => {
      try {
        return JSON.parse(rawContents)
      } catch (error) {
        throw new Error(`Unable to parse custom dataset: ${(error as Error).message}`)
      }
    })()

    const parsed = customDatasetSchema.safeParse(parsedJson)

    if (!parsed.success) {
      throw new Error('Custom dataset has an invalid format')
    }

    const baseEntries = parsed.data
      .map(toBaseEntry)
      .filter((entry): entry is KevBaseEntry => entry !== null)

    const cvelistResults = await mapWithConcurrency(
      baseEntries,
      CVELIST_ENRICHMENT_CONCURRENCY,
      async base => {
        if (!shouldEnrichWithCvelist(base)) {
          return { entry: base, impacts: [], hit: false }
        }
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
      const message = `Custom CVEList enrichment (${cvelistHits} hits, ${cvelistMisses} misses)`
      markTaskProgress('custom', 0, 0, message)
    }

    const impactRecordMap = new Map<string, VulnerabilityImpactRecord[]>()
    for (const result of cvelistResults) {
      if (result.impacts.length) {
        impactRecordMap.set(result.entry.id, result.impacts)
      }
    }

    const enrichedEntries = cvelistResults.map(result => enrichEntry(result.entry))
    const entryRecords = buildEntryDiffRecords(enrichedEntries, 'custom', impactRecordMap)
    const totalEntries = entryRecords.length
    const useIncremental = strategy === 'incremental'

    if (!useIncremental) {
      setImportPhase('savingCustom', {
        message: 'Saving curated entries to the local cache',
        completed: 0,
        total: totalEntries
      })
      markTaskProgress('custom', 0, totalEntries, 'Saving curated entries to the local cache')

      await db
        .delete(tables.vulnerabilityEntries)
        .where(eq(tables.vulnerabilityEntries.source, 'custom'))
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
          const message = `Saving curated entries to the local cache (${index + 1} of ${entryRecords.length})`
          setImportPhase('savingCustom', {
            message,
            completed: index + 1,
            total: entryRecords.length
          })
          markTaskProgress('custom', index + 1, entryRecords.length, message)
        }
      }

      const importedAt = new Date().toISOString()
      await Promise.all([
        setMetadataValue('custom.lastImportAt', importedAt),
        setMetadataValue('custom.totalCount', String(totalEntries)),
        setMetadataValue('custom.lastNewCount', String(totalEntries)),
        setMetadataValue('custom.lastUpdatedCount', '0'),
        setMetadataValue('custom.lastSkippedCount', '0'),
        setMetadataValue('custom.lastRemovedCount', '0'),
        setMetadataValue('custom.lastImportStrategy', 'full')
      ])

      markTaskComplete('custom', `${totalEntries.toLocaleString()} curated entries cached`)

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

    const existingMap = await loadExistingEntryRecords(db, 'custom')
    const { newRecords, updatedRecords, unchangedRecords, removedIds } =
      diffEntryRecords(entryRecords, existingMap)
    const totalChanges = newRecords.length + updatedRecords.length

    if (totalChanges > 0) {
      const message = 'Saving curated changes to the local cache'
      setImportPhase('savingCustom', {
        message,
        completed: 0,
        total: totalChanges
      })
      markTaskProgress('custom', 0, totalChanges, message)
    } else if (removedIds.length > 0) {
      const message = `Removing ${removedIds.length.toLocaleString()} retired curated entr${removedIds.length === 1 ? 'y' : 'ies'}`
      setImportPhase('savingCustom', {
        message,
        completed: 0,
        total: 0
      })
      markTaskProgress('custom', 0, 0, message)
    } else {
      const message = 'Curated catalog already up to date'
      setImportPhase('savingCustom', {
        message,
        completed: 0,
        total: 0
      })
      markTaskProgress('custom', 0, 0, message)
    }

    let processed = 0
    for (const record of newRecords) {
      await persistEntryRecord(db, record, 'insert')
      const completed = processed + 1
      if (totalChanges > 0) {
        const message = `Saving curated changes to the local cache (${completed} of ${totalChanges})`
        setImportPhase('savingCustom', { message, completed, total: totalChanges })
        markTaskProgress('custom', completed, totalChanges, message)
      }
      processed += 1
    }

    for (const record of updatedRecords) {
      await persistEntryRecord(db, record, 'update')
      const completed = processed + 1
      if (totalChanges > 0) {
        const message = `Saving curated changes to the local cache (${completed} of ${totalChanges})`
        setImportPhase('savingCustom', { message, completed, total: totalChanges })
        markTaskProgress('custom', completed, totalChanges, message)
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
      setMetadataValue('custom.lastImportAt', importedAt),
      setMetadataValue('custom.totalCount', String(totalEntries)),
      setMetadataValue('custom.lastNewCount', String(newRecords.length)),
      setMetadataValue('custom.lastUpdatedCount', String(updatedRecords.length)),
      setMetadataValue('custom.lastSkippedCount', String(unchangedRecords.length)),
      setMetadataValue('custom.lastRemovedCount', String(removedIds.length)),
      setMetadataValue('custom.lastImportStrategy', 'incremental')
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
      ? `Curated catalog updated (${changeSegments.join(', ')})`
      : 'Curated catalog already up to date'

    markTaskComplete('custom', summaryLabel)

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
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Curated feed import failed'
    markTaskError('custom', message)
    throw error
  }
}
