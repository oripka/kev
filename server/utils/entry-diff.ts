import { eq, inArray } from 'drizzle-orm'
import type { KevEntry } from '~/types'
import { tables } from '../database/client'
import type { DrizzleDatabase } from '../database/client'
import type { VulnerabilityImpactRecord } from './cvelist'

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
  cvssSeverity: KevEntry['cvssSeverity'] | null
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

export type CategoryRecord = {
  entryId: string
  categoryType: 'domain' | 'exploit' | 'vulnerability'
  value: string
  name: string
}

export type EntryDiffRecord = {
  values: EntryRowValues
  impacts: ImpactRecord[]
  categories: CategoryRecord[]
  signature: string
}

const toJson = (value: unknown): string => JSON.stringify(value ?? [])

const normaliseStoredSeverity = (
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

export const createEntryValues = (
  entry: KevEntry,
  source: string
): EntryRowValues => ({
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
  sourceUrl: entry.sourceUrl,
  pocUrl: entry.pocUrl,
  pocPublishedAt: entry.pocPublishedAt,
  referenceLinks: toJson(entry.references),
  aliases: toJson(entry.aliases),
  affectedProducts: toJson(entry.affectedProducts),
  problemTypes: toJson(entry.problemTypes),
  metasploitModulePath: entry.metasploitModulePath,
  metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
  internetExposed: entry.internetExposed ? 1 : 0
})

export const buildCategoryRecords = (entry: KevEntry): CategoryRecord[] => {
  const records: CategoryRecord[] = []
  const pushCategories = (
    values: string[],
    type: CategoryRecord['categoryType']
  ) => {
    for (const value of values) {
      if (!value) {
        continue
      }
      records.push({ entryId: entry.id, categoryType: type, value, name: value })
    }
  }

  pushCategories(entry.domainCategories, 'domain')
  pushCategories(entry.exploitLayers, 'exploit')
  pushCategories(entry.vulnerabilityCategories, 'vulnerability')

  return records
}

export const normaliseImpacts = (
  impacts: VulnerabilityImpactRecord[]
): ImpactRecord[] => {
  const deduped = new Map<string, ImpactRecord>()

  for (const impact of impacts) {
    const record: ImpactRecord = {
      entryId: impact.entryId,
      vendor: impact.vendor,
      vendorKey: impact.vendorKey,
      product: impact.product,
      productKey: impact.productKey,
      status: impact.status ?? '',
      versionRange: impact.versionRange ?? '',
      source: impact.source
    }

    const key = [
      record.vendorKey,
      record.productKey,
      record.status,
      record.versionRange,
      record.source
    ].join('|')

    if (!deduped.has(key)) {
      deduped.set(key, record)
    }
  }

  return [...deduped.values()]
}

const sortImpacts = (records: ImpactRecord[]) =>
  records
    .map(record => ({ ...record }))
    .sort((first, second) => {
      const firstKey = [
        first.vendorKey,
        first.productKey,
        first.status,
        first.versionRange,
        first.source
      ].join('|')
      const secondKey = [
        second.vendorKey,
        second.productKey,
        second.status,
        second.versionRange,
        second.source
      ].join('|')
      return firstKey.localeCompare(secondKey)
    })

const sortCategories = (records: CategoryRecord[]) =>
  records
    .map(record => ({ ...record }))
    .sort((first, second) => {
      const firstKey = `${first.categoryType}|${first.value}`
      const secondKey = `${second.categoryType}|${second.value}`
      return firstKey.localeCompare(secondKey)
    })

export const createRecordSignature = (
  values: EntryRowValues,
  impacts: ImpactRecord[],
  categories: CategoryRecord[]
) =>
  JSON.stringify({
    values: { ...values },
    impacts: sortImpacts(impacts),
    categories: sortCategories(categories)
  })

export const buildEntryDiffRecords = (
  entries: KevEntry[],
  source: string,
  impactMap: Map<string, VulnerabilityImpactRecord[]>
): EntryDiffRecord[] =>
  entries.map(entry => {
    const values = createEntryValues(entry, source)
    const categories = buildCategoryRecords(entry)
    const impacts = normaliseImpacts(impactMap.get(entry.id) ?? [])
    return {
      values,
      categories,
      impacts,
      signature: createRecordSignature(values, impacts, categories)
    }
  })

type ExistingEntryRow = {
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
}

const createEntryValuesFromRow = (
  row: ExistingEntryRow,
  source: string
): EntryRowValues => ({
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

type ExistingEntryBucket = {
  values: EntryRowValues
  impacts: ImpactRecord[]
  categories: CategoryRecord[]
  signature: string
}

const MAX_BATCH_PARAMETERS = 80
const IMPACT_COLUMN_COUNT = 8
const CATEGORY_COLUMN_COUNT = 4
const IMPACT_BATCH_SIZE = Math.max(1, Math.floor(MAX_BATCH_PARAMETERS / IMPACT_COLUMN_COUNT))
const CATEGORY_BATCH_SIZE = Math.max(1, Math.floor(MAX_BATCH_PARAMETERS / CATEGORY_COLUMN_COUNT))

const chunk = <T>(items: T[], size: number): T[][] => {
  if (items.length <= size) {
    return [items]
  }
  const chunks: T[][] = []
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size))
  }
  return chunks
}

export const insertImpactRecords = (
  db: DrizzleDatabase,
  records: ImpactRecord[]
) => {
  if (!records.length) {
    return
  }
  for (const batch of chunk(records, IMPACT_BATCH_SIZE)) {
    db.insert(tables.vulnerabilityEntryImpacts).values(batch).run()
  }
}

export const insertCategoryRecords = (
  db: DrizzleDatabase,
  records: CategoryRecord[]
) => {
  if (!records.length) {
    return
  }
  for (const batch of chunk(records, CATEGORY_BATCH_SIZE)) {
    db.insert(tables.vulnerabilityEntryCategories).values(batch).run()
  }
}

export const loadExistingEntryRecords = async (
  db: DrizzleDatabase,
  source: string
): Promise<Map<string, ExistingEntryBucket>> => {
  const rows = await db
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
      metasploitModulePublishedAt:
        tables.vulnerabilityEntries.metasploitModulePublishedAt,
      internetExposed: tables.vulnerabilityEntries.internetExposed
    })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, source))
    .all()

  const typedRows = rows as ExistingEntryRow[]

  const map = new Map<string, ExistingEntryBucket>()

  for (const row of typedRows) {
    const values = createEntryValuesFromRow(row, source)
    map.set(row.id, { values, impacts: [], categories: [], signature: '' })
  }

  const existingIds = Array.from(map.keys())
  if (!existingIds.length) {
    return map
  }

  const impactRows: ImpactRecord[] = []
  for (const idChunk of chunk(existingIds, IMPACT_BATCH_SIZE)) {
    const rows = await db
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
      .where(inArray(tables.vulnerabilityEntryImpacts.entryId, idChunk))
      .all()
    impactRows.push(...(rows as ImpactRecord[]))
  }

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
      status: impact.status,
      versionRange: impact.versionRange,
      source: impact.source
    })
  }

  const categoryRows: CategoryRecord[] = []
  for (const idChunk of chunk(existingIds, CATEGORY_BATCH_SIZE)) {
    const rows = await db
      .select({
        entryId: tables.vulnerabilityEntryCategories.entryId,
        categoryType: tables.vulnerabilityEntryCategories.categoryType,
        value: tables.vulnerabilityEntryCategories.value,
        name: tables.vulnerabilityEntryCategories.name
      })
      .from(tables.vulnerabilityEntryCategories)
      .where(inArray(tables.vulnerabilityEntryCategories.entryId, idChunk))
      .all()
    categoryRows.push(...(rows as CategoryRecord[]))
  }

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
    bucket.signature = createRecordSignature(
      bucket.values,
      bucket.impacts,
      bucket.categories
    )
  }

  return map
}

export const diffEntryRecords = (
  records: EntryDiffRecord[],
  existingMap: Map<string, ExistingEntryBucket>
) => {
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

  const removedIds = Array.from(existingMap.keys()).filter(
    id => !seenExisting.has(id)
  )

  return { newRecords, updatedRecords, unchangedRecords, removedIds }
}

export const persistEntryRecord = (
  db: DrizzleDatabase,
  record: EntryDiffRecord,
  action: 'insert' | 'update'
) => {
  const { values, impacts, categories } = record

  if (action === 'insert') {
    db.insert(tables.vulnerabilityEntries).values(values).run()
  } else {
    const { id, ...updateValues } = values
    db
      .update(tables.vulnerabilityEntries)
      .set(updateValues)
      .where(eq(tables.vulnerabilityEntries.id, id))
      .run()
  }

  db
    .delete(tables.vulnerabilityEntryImpacts)
    .where(eq(tables.vulnerabilityEntryImpacts.entryId, values.id))
    .run()

  insertImpactRecords(db, impacts)

  db
    .delete(tables.vulnerabilityEntryCategories)
    .where(eq(tables.vulnerabilityEntryCategories.entryId, values.id))
    .run()

  insertCategoryRecords(db, categories)
}
