import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { eq } from 'drizzle-orm'
import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'
import { setMetadata } from './sqlite'
import { setImportPhase } from './import-progress'

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

const toJson = (value: unknown): string => JSON.stringify(value ?? [])

const toBaseEntry = (item: z.infer<typeof historicEntrySchema>): KevBaseEntry | null => {
  const cveId = item.cve?.trim()
  if (!cveId) {
    return null
  }

  const normalised = normaliseVendorProduct({ vendor: item.vendor, product: item.product })
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
    references: [],
    aliases: [cveId.toUpperCase()],
    internetExposed: false
  }
}

const collectDimensionRecords = (
  entryId: string,
  entry: ReturnType<typeof enrichEntry>
): Array<{ entryId: string; categoryType: string; value: string; name: string }> => {
  const records: Array<{ entryId: string; categoryType: string; value: string; name: string }> = []

  const push = (values: string[], type: 'domain' | 'exploit' | 'vulnerability') => {
    for (const value of values) {
      if (!value) {
        continue
      }
      records.push({ entryId, categoryType: type, value, name: value })
    }
  }

  push(entry.domainCategories, 'domain')
  push(entry.exploitLayers, 'exploit')
  push(entry.vulnerabilityCategories, 'vulnerability')

  return records
}

export const importHistoricCatalog = async (
  db: DrizzleDatabase
): Promise<{ imported: number }> => {
  setImportPhase('fetchingHistoric', {
    message: 'Loading historic exploit dataset',
    completed: 0,
    total: 0
  })

  const datasetPath = join(process.cwd(), 'historic.json')

  let rawContents: string
  try {
    rawContents = await readFile(datasetPath, 'utf8')
  } catch (error) {
    throw new Error(`Unable to read historic dataset: ${(error as Error).message}`)
  }

  let parsedJson: unknown
  try {
    parsedJson = JSON.parse(rawContents)
  } catch (error) {
    throw new Error(`Unable to parse historic dataset: ${(error as Error).message}`)
  }

  const parsed = historicDatasetSchema.safeParse(parsedJson)

  if (!parsed.success) {
    throw new Error('Historic dataset has an invalid format')
  }

  const baseEntries = parsed.data
    .map(toBaseEntry)
    .filter((entry): entry is KevBaseEntry => entry !== null)

  const enrichedEntries = baseEntries.map(entry => enrichEntry(entry))

  setImportPhase('savingHistoric', {
    message: 'Saving historic entries to the local cache',
    completed: 0,
    total: enrichedEntries.length
  })

  db.transaction(tx => {
    tx.delete(tables.vulnerabilityEntries)
      .where(eq(tables.vulnerabilityEntries.source, 'historic'))
      .run()

    for (let index = 0; index < enrichedEntries.length; index += 1) {
      const entry = enrichedEntries[index]
      const entryId = entry.id

      tx
        .insert(tables.vulnerabilityEntries)
        .values({
          id: entryId,
          cveId: entry.cveId,
          source: 'historic',
          vendor: entry.vendor,
          product: entry.product,
          vulnerabilityName: entry.vulnerabilityName,
          description: entry.description,
          requiredAction: entry.requiredAction,
          dateAdded: entry.dateAdded,
          dueDate: entry.dueDate,
          ransomwareUse: entry.ransomwareUse,
          notes: toJson(entry.notes),
          cwes: toJson(entry.cwes),
          cvssScore: entry.cvssScore,
          cvssVector: entry.cvssVector,
          cvssVersion: entry.cvssVersion,
          cvssSeverity: entry.cvssSeverity,
          epssScore: entry.epssScore,
          assigner: entry.assigner,
          datePublished: entry.datePublished,
          dateUpdated: entry.dateUpdated,
          exploitedSince: entry.exploitedSince,
          sourceUrl: entry.sourceUrl,
          referenceLinks: toJson(entry.references),
          aliases: toJson(entry.aliases),
          internetExposed: entry.internetExposed ? 1 : 0
        })
        .run()

      const dimensions = collectDimensionRecords(entryId, entry)

      if (dimensions.length) {
        tx.insert(tables.vulnerabilityEntryCategories).values(dimensions).run()
      }

      if ((index + 1) % 25 === 0 || index + 1 === enrichedEntries.length) {
        setImportPhase('savingHistoric', {
          message: `Saving historic entries to the local cache (${index + 1} of ${enrichedEntries.length})`,
          completed: index + 1,
          total: enrichedEntries.length
        })
      }
    }
  })

  const importedAt = new Date().toISOString()
  setMetadata('historic.lastImportAt', importedAt)
  setMetadata('historic.totalCount', String(enrichedEntries.length))

  return { imported: enrichedEntries.length }
}
