import { defineEventHandler } from 'h3'
import { eq } from 'drizzle-orm'
import { rebuildCatalog } from '../../utils/catalog'
import { rebuildProductCatalog } from '../../utils/product-catalog'
import { tables, useDrizzle } from '../../database/client'
import {
  completeClassificationProgress,
  failClassificationProgress,
  setClassificationPhase,
  startClassificationProgress,
  updateClassificationProgress
} from '../../utils/classification-progress'
import { requireAdminKey } from '../../utils/adminAuth'
import { enrichEntry, type KevBaseEntry } from '~/utils/classification'
import type { CatalogSource, KevAffectedProduct, KevProblemType } from '~/types'

type VulnerabilityEntryRow = typeof tables.vulnerabilityEntries.$inferSelect

const isCatalogSource = (value: string | null | undefined): value is CatalogSource =>
  value === 'kev' ||
  value === 'enisa' ||
  value === 'historic' ||
  value === 'metasploit' ||
  value === 'poc'

const parseStringArray = (value: string | null | undefined): string[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }

    return parsed
      .filter((item): item is string => typeof item === 'string')
      .map(item => item.trim())
      .filter(item => item.length > 0)
  } catch {
    return []
  }
}

const parseJsonObjectArray = <T>(value: string | null | undefined): T[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }

    return parsed.filter((item): item is T => typeof item === 'object' && item !== null)
  } catch {
    return []
  }
}

const toCvssSeverity = (value: unknown): KevBaseEntry['cvssSeverity'] => {
  if (value === 'None' || value === 'Low' || value === 'Medium' || value === 'High' || value === 'Critical') {
    return value
  }
  return null
}

const toBaseEntry = (row: VulnerabilityEntryRow): KevBaseEntry => {
  const source = isCatalogSource(row.source) ? row.source : null
  const notes = parseStringArray(row.notes)
  const references = parseStringArray(row.referenceLinks)
  const aliases = parseStringArray(row.aliases)
  const affectedProducts = parseJsonObjectArray<KevAffectedProduct>(row.affectedProducts)
  const problemTypes = parseJsonObjectArray<KevProblemType>(row.problemTypes)

  return {
    id: row.id,
    cveId: row.cveId ?? row.id,
    sources: source ? [source] : [],
    vendor: row.vendor ?? '',
    vendorKey: row.vendorKey ?? '',
    product: row.product ?? '',
    productKey: row.productKey ?? '',
    affectedProducts,
    problemTypes,
    vulnerabilityName: row.vulnerabilityName ?? '',
    description: row.description ?? '',
    requiredAction: row.requiredAction ?? null,
    dateAdded: row.dateAdded ?? '',
    dueDate: row.dueDate ?? null,
    ransomwareUse: row.ransomwareUse ?? null,
    notes,
    cwes: parseStringArray(row.cwes),
    cvssScore: typeof row.cvssScore === 'number' ? row.cvssScore : null,
    cvssVector: row.cvssVector ?? null,
    cvssVersion: row.cvssVersion ?? null,
    cvssSeverity: toCvssSeverity(row.cvssSeverity),
    epssScore: typeof row.epssScore === 'number' ? row.epssScore : null,
    assigner: row.assigner ?? null,
    datePublished: row.datePublished ?? null,
    dateUpdated: row.dateUpdated ?? null,
    exploitedSince: row.exploitedSince ?? null,
    sourceUrl: row.sourceUrl ?? null,
    pocUrl: row.pocUrl ?? null,
    pocPublishedAt: row.pocPublishedAt ?? null,
    references,
    aliases,
    metasploitModulePath: row.metasploitModulePath ?? null,
    metasploitModulePublishedAt: row.metasploitModulePublishedAt ?? null,
    internetExposed: row.internetExposed === 1
  }
}

const buildCategoryRecords = (entryId: string, entry: ReturnType<typeof enrichEntry>) => {
  const records: Array<{ entryId: string; categoryType: string; value: string; name: string }> = []

  const append = (type: 'domain' | 'exploit' | 'vulnerability', values: string[]) => {
    for (const value of values) {
      if (!value || value === 'Other') {
        continue
      }
      records.push({ entryId, categoryType: type, value, name: value })
    }
  }

  append('domain', entry.domainCategories)
  append('exploit', entry.exploitLayers)
  append('vulnerability', entry.vulnerabilityCategories)

  return records
}

export default defineEventHandler(async event => {
  requireAdminKey(event)

  const db = useDrizzle()

  startClassificationProgress('Preparing catalog reclassification…', 0)

  try {
    const existingEntries = (await db
      .select()
      .from(tables.vulnerabilityEntries)
      .all()) as VulnerabilityEntryRow[]

    const totalEntries = existingEntries.length

    setClassificationPhase('enriching', {
      total: totalEntries,
      completed: 0,
      message:
        totalEntries > 0
          ? `Re-enriching ${totalEntries.toLocaleString()} vulnerability entries`
          : 'Re-enriching vulnerability entries…'
    })

    const categoryRecords: Array<{
      entryId: string
      categoryType: string
      value: string
      name: string
    }> = []
    const exposureUpdates: Array<{ id: string; value: number }> = []

    for (let index = 0; index < existingEntries.length; index += 1) {
      const row = existingEntries[index]
      const baseEntry = toBaseEntry(row)
      const enriched = enrichEntry(baseEntry)

      exposureUpdates.push({ id: row.id, value: enriched.internetExposed ? 1 : 0 })
      categoryRecords.push(...buildCategoryRecords(row.id, enriched))

      if ((index + 1) % 50 === 0 || index + 1 === totalEntries) {
        const message =
          totalEntries > 0
            ? `Re-enriching cached entries (${(index + 1).toLocaleString()} of ${totalEntries.toLocaleString()})`
            : 'Re-enriching cached entries…'
        setClassificationPhase('enriching', {
          total: totalEntries,
          completed: index + 1,
          message
        })
      }
    }

    setClassificationPhase('enriching', {
      total: totalEntries,
      completed: totalEntries,
      message:
        totalEntries > 0
          ? `Re-enrichment complete (${totalEntries.toLocaleString()} entries updated)`
          : 'Re-enrichment complete.'
    })

    await db.delete(tables.vulnerabilityEntryCategories).run()

    if (categoryRecords.length) {
      const chunkSize = 200
      for (let offset = 0; offset < categoryRecords.length; offset += chunkSize) {
        const batch = categoryRecords.slice(offset, offset + chunkSize)
        await db.insert(tables.vulnerabilityEntryCategories).values(batch).run()
      }
    }

    if (exposureUpdates.length) {
      const chunkSize = 200
      const batchCapableDb = db as { batch?: (queries: unknown[]) => Promise<unknown> }

      for (let offset = 0; offset < exposureUpdates.length; offset += chunkSize) {
        const chunk = exposureUpdates.slice(offset, offset + chunkSize)

        if (typeof batchCapableDb.batch === 'function') {
          await batchCapableDb.batch(
            chunk.map(update =>
              db
                .update(tables.vulnerabilityEntries)
                .set({ internetExposed: update.value })
                .where(eq(tables.vulnerabilityEntries.id, update.id))
            )
          )
          continue
        }

        for (const update of chunk) {
          await db
            .update(tables.vulnerabilityEntries)
            .set({ internetExposed: update.value })
            .where(eq(tables.vulnerabilityEntries.id, update.id))
            .run()
        }
      }
    }

    const summary = await rebuildCatalog(db, {
      onStart(total) {
        setClassificationPhase('rebuilding', {
          total,
          completed: 0,
          message:
            total > 0
              ? `Reclassifying cached catalog (0 of ${total})`
              : 'Reclassifying cached catalog…'
        })
      },
      onProgress(completed, total) {
        const message =
          total > 0
            ? `Reclassifying cached catalog (${completed} of ${total})`
            : 'Reclassifying cached catalog…'
        updateClassificationProgress(completed, total, message)
      }
    })

    await rebuildProductCatalog(db)

    const message = `Reclassified ${summary.count.toLocaleString()} catalog entries`
    completeClassificationProgress(`${message}.`)

    return {
      reclassified: summary.count,
      earliest: summary.earliest,
      latest: summary.latest
    }
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Unable to reclassify cached data'

    failClassificationProgress(message)
    throw error
  }
})
