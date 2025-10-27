import { eq, inArray } from 'drizzle-orm'
import type { KevEntry } from '~/types'
import type { VulnerabilityImpactRecord } from './cvelist'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'

const toJson = (value: unknown): string => JSON.stringify(value ?? [])

export type ImportStrategy = 'full' | 'incremental'

export type EntryRowValues = {
  id: string
  cveId: string
  source: string
  vendor: string
  product: string
  vendorKey: string
  productKey: string
  vulnerabilityName: string
  description: string
  requiredAction: string | null
  dateAdded: string
  dueDate: string | null
  ransomwareUse: string | null
  notes: string
  cwes: string
  cvssScore: number | null
  cvssVector: string | null
  cvssVersion: string | null
  cvssSeverity: KevEntry['cvssSeverity']
  epssScore: number | null
  assigner: string | null
  datePublished: string | null
  dateUpdated: string | null
  exploitedSince: string | null
  sourceUrl: string | null
  pocUrl: string | null
  pocPublishedAt: string | null
  referenceLinks: string
  aliases: string
  affectedProducts: string
  problemTypes: string
  metasploitModulePath: string | null
  metasploitModulePublishedAt: string | null
  internetExposed: number
}

export type CategoryRecord = {
  entryId: string
  categoryType: 'domain' | 'exploit' | 'vulnerability'
  value: string
  name: string
}

export type ImpactRecord = {
  entryId: string
  vendor: string
  vendorKey: string
  product: string
  productKey: string
  status: string
  versionRange: string
  source: string
}

export type EntryDiffRecord = {
  values: EntryRowValues
  impacts: ImpactRecord[]
  categories: CategoryRecord[]
  signature: string
}

type ExistingRecord = {
  values: EntryRowValues
  impacts: ImpactRecord[]
  categories: CategoryRecord[]
  signature: string
}

type ExistingRecordMap = Map<string, ExistingRecord>

export const normaliseStoredSeverity = (
  value: unknown
): KevEntry['cvssSeverity'] | null => {
  if (typeof value !== 'string') {
    return null
  }

  switch (value) {
    case 'None':
    case 'Low':
    case 'Medium':
    case 'High':
    case 'Critical':
      return value
    default:
      return null
  }
}

const buildCategoryRecords = (entry: KevEntry): CategoryRecord[] => {
  const records: CategoryRecord[] = []
  const pushCategories = (values: string[], type: CategoryRecord['categoryType']) => {
    for (const value of values) {
      records.push({ entryId: entry.id, categoryType: type, value, name: value })
    }
  }
  pushCategories(entry.domainCategories, 'domain')
  pushCategories(entry.exploitLayers, 'exploit')
  pushCategories(entry.vulnerabilityCategories, 'vulnerability')
  return records
}

const normaliseImpacts = (impacts: VulnerabilityImpactRecord[]): ImpactRecord[] => {
  return impacts.map(impact => ({
    entryId: impact.entryId,
    vendor: impact.vendor,
    vendorKey: impact.vendorKey,
    product: impact.product,
    productKey: impact.productKey,
    status: impact.status ?? '',
    versionRange: impact.versionRange ?? '',
    source: impact.source
  }))
}

const sortImpacts = (records: ImpactRecord[]) => {
  return records
    .map(record => ({ ...record }))
    .sort((first, second) => {
      const firstKey = [first.vendorKey, first.productKey, first.status, first.versionRange, first.source].join('|')
      const secondKey = [second.vendorKey, second.productKey, second.status, second.versionRange, second.source].join('|')
      return firstKey.localeCompare(secondKey)
    })
}

const sortCategories = (records: CategoryRecord[]) => {
  return records
    .map(record => ({ ...record }))
    .sort((first, second) => {
      const firstKey = `${first.categoryType}|${first.value}`
      const secondKey = `${second.categoryType}|${second.value}`
      return firstKey.localeCompare(secondKey)
    })
}

const createRecordSignature = (
  values: EntryRowValues,
  impacts: ImpactRecord[],
  categories: CategoryRecord[]
) => {
  return JSON.stringify({
    values: { ...values },
    impacts: sortImpacts(impacts),
    categories: sortCategories(categories)
  })
}

export const createEntryValues = (entry: KevEntry, source: string): EntryRowValues => ({
  id: entry.id,
  cveId: entry.cveId,
  source,
  vendor: entry.vendor,
  product: entry.product,
  vendorKey: entry.vendorKey,
  productKey: entry.productKey,
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
  sourceUrl: entry.sourceUrl ?? null,
  pocUrl: entry.pocUrl ?? null,
  pocPublishedAt: entry.pocPublishedAt ?? null,
  referenceLinks: toJson(entry.references),
  aliases: toJson(entry.aliases),
  affectedProducts: toJson(entry.affectedProducts),
  problemTypes: toJson(entry.problemTypes),
  metasploitModulePath: entry.metasploitModulePath,
  metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
  internetExposed: entry.internetExposed ? 1 : 0
})

export const createEntryRecords = (
  entries: KevEntry[],
  source: string,
  impacts: Map<string, VulnerabilityImpactRecord[]>
): EntryDiffRecord[] => {
  return entries.map(entry => {
    const values = createEntryValues(entry, source)
    const categories = buildCategoryRecords(entry)
    const impactRecords = normaliseImpacts(impacts.get(entry.id) ?? [])
    return {
      values,
      impacts: impactRecords,
      categories,
      signature: createRecordSignature(values, impactRecords, categories)
    }
  })
}

const createEntryValuesFromRow = (row: {
  id: string
  cveId: string | null
  vendor: string | null
  product: string | null
  vendorKey: string | null
  productKey: string | null
  vulnerabilityName: string | null
  description: string | null
  requiredAction: string | null
  dateAdded: string | null
  dueDate: string | null
  ransomwareUse: string | null
  notes: string | null
  cwes: string | null
  cvssScore: number | null
  cvssVector: string | null
  cvssVersion: string | null
  cvssSeverity: string | null
  epssScore: number | null
  assigner: string | null
  datePublished: string | null
  dateUpdated: string | null
  exploitedSince: string | null
  sourceUrl: string | null
  pocUrl: string | null
  pocPublishedAt: string | null
  referenceLinks: string | null
  aliases: string | null
  affectedProducts: string | null
  problemTypes: string | null
  metasploitModulePath: string | null
  metasploitModulePublishedAt: string | null
  internetExposed: number | null
}, source: string): EntryRowValues => ({
  id: row.id,
  cveId: row.cveId ?? '',
  source,
  vendor: row.vendor ?? '',
  product: row.product ?? '',
  vendorKey: row.vendorKey ?? '',
  productKey: row.productKey ?? '',
  vulnerabilityName: row.vulnerabilityName ?? '',
  description: row.description ?? '',
  requiredAction: row.requiredAction ?? null,
  dateAdded: row.dateAdded ?? '',
  dueDate: row.dueDate ?? null,
  ransomwareUse: row.ransomwareUse ?? null,
  notes: row.notes ?? '[]',
  cwes: row.cwes ?? '[]',
  cvssScore: typeof row.cvssScore === 'number' ? row.cvssScore : null,
  cvssVector: row.cvssVector ?? null,
  cvssVersion: row.cvssVersion ?? null,
  cvssSeverity: normaliseStoredSeverity(row.cvssSeverity),
  epssScore: typeof row.epssScore === 'number' ? row.epssScore : null,
  assigner: row.assigner ?? null,
  datePublished: row.datePublished ?? null,
  dateUpdated: row.dateUpdated ?? null,
  exploitedSince: row.exploitedSince ?? null,
  sourceUrl: row.sourceUrl ?? null,
  pocUrl: row.pocUrl ?? null,
  pocPublishedAt: row.pocPublishedAt ?? null,
  referenceLinks: row.referenceLinks ?? '[]',
  aliases: row.aliases ?? '[]',
  affectedProducts: row.affectedProducts ?? '[]',
  problemTypes: row.problemTypes ?? '[]',
  metasploitModulePath: row.metasploitModulePath ?? null,
  metasploitModulePublishedAt: row.metasploitModulePublishedAt ?? null,
  internetExposed: typeof row.internetExposed === 'number' ? row.internetExposed : 0
})

const loadExistingRecords = (db: DrizzleDatabase, source: string): ExistingRecordMap => {
  const rows = db
    .select({
      id: tables.vulnerabilityEntries.id,
      cveId: tables.vulnerabilityEntries.cveId,
      vendor: tables.vulnerabilityEntries.vendor,
      product: tables.vulnerabilityEntries.product,
      vendorKey: tables.vulnerabilityEntries.vendorKey,
      productKey: tables.vulnerabilityEntries.productKey,
      vulnerabilityName: tables.vulnerabilityEntries.vulnerabilityName,
      description: tables.vulnerabilityEntries.description,
      requiredAction: tables.vulnerabilityEntries.requiredAction,
      dateAdded: tables.vulnerabilityEntries.dateAdded,
      dueDate: tables.vulnerabilityEntries.dueDate,
      ransomwareUse: tables.vulnerabilityEntries.ransomwareUse,
      notes: tables.vulnerabilityEntries.notes,
      cwes: tables.vulnerabilityEntries.cwes,
      cvssScore: tables.vulnerabilityEntries.cvssScore,
      cvssVector: tables.vulnerabilityEntries.cvssVector,
      cvssVersion: tables.vulnerabilityEntries.cvssVersion,
      cvssSeverity: tables.vulnerabilityEntries.cvssSeverity,
      epssScore: tables.vulnerabilityEntries.epssScore,
      assigner: tables.vulnerabilityEntries.assigner,
      datePublished: tables.vulnerabilityEntries.datePublished,
      dateUpdated: tables.vulnerabilityEntries.dateUpdated,
      exploitedSince: tables.vulnerabilityEntries.exploitedSince,
      sourceUrl: tables.vulnerabilityEntries.sourceUrl,
      pocUrl: tables.vulnerabilityEntries.pocUrl,
      pocPublishedAt: tables.vulnerabilityEntries.pocPublishedAt,
      referenceLinks: tables.vulnerabilityEntries.referenceLinks,
      aliases: tables.vulnerabilityEntries.aliases,
      affectedProducts: tables.vulnerabilityEntries.affectedProducts,
      problemTypes: tables.vulnerabilityEntries.problemTypes,
      metasploitModulePath: tables.vulnerabilityEntries.metasploitModulePath,
      metasploitModulePublishedAt: tables.vulnerabilityEntries.metasploitModulePublishedAt,
      internetExposed: tables.vulnerabilityEntries.internetExposed
    })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, source))
    .all()

  const map: ExistingRecordMap = new Map()

  for (const row of rows) {
    map.set(row.id, {
      values: createEntryValuesFromRow(row, source),
      impacts: [],
      categories: [],
      signature: ''
    })
  }

  const existingIds = Array.from(map.keys())

  if (!existingIds.length) {
    return map
  }

  const impactRows = db
    .select({
      entryId: tables.vulnerabilityEntryImpacts.entryId,
      vendor: tables.vulnerabilityEntryImpacts.vendor,
      vendorKey: tables.vulnerabilityEntryImpacts.vendorKey,
      product: tables.vulnerabilityEntryImpacts.product,
      productKey: tables.vulnerabilityEntryImpacts.productKey,
      status: tables.vulnerabilityEntryImpacts.status,
      versionRange: tables.vulnerabilityEntryImpacts.versionRange,
      source: tables.vulnerabilityEntryImpacts.source
    })
    .from(tables.vulnerabilityEntryImpacts)
    .where(inArray(tables.vulnerabilityEntryImpacts.entryId, existingIds))
    .all()

  for (const impact of impactRows) {
    const bucket = map.get(impact.entryId)
    if (!bucket) {
      continue
    }
    bucket.impacts.push({
      entryId: impact.entryId,
      vendor: impact.vendor,
      vendorKey: impact.vendorKey,
      product: impact.product,
      productKey: impact.productKey,
      status: impact.status ?? '',
      versionRange: impact.versionRange ?? '',
      source: impact.source
    })
  }

  const categoryRows = db
    .select({
      entryId: tables.vulnerabilityEntryCategories.entryId,
      categoryType: tables.vulnerabilityEntryCategories.categoryType,
      value: tables.vulnerabilityEntryCategories.value,
      name: tables.vulnerabilityEntryCategories.name
    })
    .from(tables.vulnerabilityEntryCategories)
    .where(inArray(tables.vulnerabilityEntryCategories.entryId, existingIds))
    .all()

  for (const category of categoryRows) {
    const bucket = map.get(category.entryId)
    if (!bucket) {
      continue
    }
    bucket.categories.push({
      entryId: category.entryId,
      categoryType: category.categoryType,
      value: category.value,
      name: category.name
    })
  }

  for (const bucket of map.values()) {
    bucket.signature = createRecordSignature(bucket.values, bucket.impacts, bucket.categories)
  }

  return map
}

type DiffResult = {
  newRecords: EntryDiffRecord[]
  updatedRecords: EntryDiffRecord[]
  unchangedRecords: EntryDiffRecord[]
  removedIds: string[]
}

const diffEntryRecords = (
  existingMap: ExistingRecordMap,
  records: EntryDiffRecord[]
): DiffResult => {
  const seenExisting = new Set<string>()
  const newRecords: EntryDiffRecord[] = []
  const updatedRecords: EntryDiffRecord[] = []
  const unchangedRecords: EntryDiffRecord[] = []

  for (const record of records) {
    const existing = existingMap.get(record.values.id)
    if (!existing) {
      newRecords.push(record)
      continue
    }

    seenExisting.add(record.values.id)

    if (existing.signature !== record.signature) {
      updatedRecords.push(record)
    } else {
      unchangedRecords.push(record)
    }
  }

  const removedIds = Array.from(existingMap.keys()).filter(id => !seenExisting.has(id))
  return { newRecords, updatedRecords, unchangedRecords, removedIds }
}

type SaveCallbacks = {
  onFullStart?: (total: number) => void
  onFullProgress?: (index: number, total: number) => void
  onIncrementalStart?: (details: { totalChanges: number; removedCount: number }) => void
  onIncrementalProgress?: (processed: number, totalChanges: number) => void
}

type SaveEntryRecordsOptions = {
  db: DrizzleDatabase
  source: string
  records: EntryDiffRecord[]
  strategy: ImportStrategy
  callbacks?: SaveCallbacks
}

type SaveResult = {
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
}

export const saveEntryRecords = ({
  db,
  source,
  records,
  strategy,
  callbacks
}: SaveEntryRecordsOptions): SaveResult => {
  const totalRecords = records.length

  if (strategy !== 'incremental') {
    db.transaction(tx => {
      tx
        .delete(tables.vulnerabilityEntries)
        .where(eq(tables.vulnerabilityEntries.source, source))
        .run()

      callbacks?.onFullStart?.(totalRecords)

      for (let index = 0; index < records.length; index += 1) {
        const record = records[index]
        tx.insert(tables.vulnerabilityEntries).values(record.values).run()

        if (record.impacts.length) {
          tx.insert(tables.vulnerabilityEntryImpacts).values(record.impacts).run()
        }

        if (record.categories.length) {
          tx.insert(tables.vulnerabilityEntryCategories).values(record.categories).run()
        }

        callbacks?.onFullProgress?.(index, totalRecords)
      }
    })

    return {
      newCount: totalRecords,
      updatedCount: 0,
      skippedCount: 0,
      removedCount: 0
    }
  }

  const existingMap = loadExistingRecords(db, source)
  const { newRecords, updatedRecords, unchangedRecords, removedIds } = diffEntryRecords(existingMap, records)
  const totalChanges = newRecords.length + updatedRecords.length

  db.transaction(tx => {
    callbacks?.onIncrementalStart?.({ totalChanges, removedCount: removedIds.length })

    const persistRecord = (record: EntryDiffRecord, action: 'insert' | 'update', processed: number) => {
      const { values, impacts, categories } = record

      if (action === 'insert') {
        tx.insert(tables.vulnerabilityEntries).values(values).run()
      } else {
        const { id, ...updateValues } = values
        tx
          .update(tables.vulnerabilityEntries)
          .set(updateValues)
          .where(eq(tables.vulnerabilityEntries.id, id))
          .run()
      }

      tx
        .delete(tables.vulnerabilityEntryImpacts)
        .where(eq(tables.vulnerabilityEntryImpacts.entryId, values.id))
        .run()

      if (impacts.length) {
        tx.insert(tables.vulnerabilityEntryImpacts).values(impacts).run()
      }

      tx
        .delete(tables.vulnerabilityEntryCategories)
        .where(eq(tables.vulnerabilityEntryCategories.entryId, values.id))
        .run()

      if (categories.length) {
        tx.insert(tables.vulnerabilityEntryCategories).values(categories).run()
      }

      if (totalChanges > 0) {
        callbacks?.onIncrementalProgress?.(processed, totalChanges)
      }
    }

    let processed = 0
    for (const record of newRecords) {
      processed += 1
      persistRecord(record, 'insert', processed)
    }
    for (const record of updatedRecords) {
      processed += 1
      persistRecord(record, 'update', processed)
    }

    if (removedIds.length) {
      tx
        .delete(tables.vulnerabilityEntries)
        .where(inArray(tables.vulnerabilityEntries.id, removedIds))
        .run()
    }
  })

  return {
    newCount: newRecords.length,
    updatedCount: updatedRecords.length,
    skippedCount: unchangedRecords.length,
    removedCount: removedIds.length
  }
}

