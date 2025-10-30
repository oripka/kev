import { and, eq, inArray, sql } from 'drizzle-orm'
import { lookupCveName } from '~/utils/cveToNameMap'
import {
  isMeaningfulProductLabel,
  isMeaningfulVendorLabel,
  normaliseVendorProduct
} from '~/utils/vendorProduct'
import type {
  CatalogSource,
  KevEntry,
  KevAffectedProduct,
  KevProblemType,
  KevEntrySummary,
  MarketProgramType,
  MarketSignal
} from '~/types'
import { tables, type DrizzleDatabase } from '../database/client'
import { setMetadataValue } from './metadata'

type RebuildCatalogOptions = {
  onStart?(total: number): void
  onProgress?(completed: number, total: number): void
  onComplete?(total: number): void
}

type VulnerabilityEntryRow = {
  id: string
  cve_id: string | null
  source: string
  vendor: string | null
  product: string | null
  vulnerability_name: string | null
  description: string | null
  required_action: string | null
  date_added: string | null
  due_date: string | null
  ransomware_use: string | null
  notes: string | null
  cwes: string | null
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  cvss_severity: string | null
  epss_score: number | null
  assigner: string | null
  date_published: string | null
  date_updated: string | null
  exploited_since: string | null
  source_url: string | null
  poc_url: string | null
  poc_published_at: string | null
  reference_links: string | null
  aliases: string | null
  vendor_key: string | null
  product_key: string | null
  affected_products: string | null
  problem_types: string | null
  metasploit_module_path: string | null
  metasploit_module_published_at: string | null
  internet_exposed: number | null
  updated_at: string | null
}

type EntryCategoryRow = {
  entry_id: string
  category_type: string
  value: string
  name: string
}

type EntryCategories = {
  domain: string[]
  exploit: string[]
  vulnerability: string[]
}

type RebuildOptions = {
  onStart?: (total: number) => void
  onProgress?: (completed: number, total: number) => void
  onComplete?: (total: number) => void
}

type CatalogDimension = 'domain' | 'exploit' | 'vulnerability'

export type CatalogEntryRow = {
  cve_id: string
  entry_id: string
  sources: string
  vendor: string
  vendor_key: string
  product: string
  product_key: string
  vulnerability_name: string
  description: string
  required_action: string | null
  date_added: string | null
  date_added_ts: number | null
  date_added_year: number | null
  due_date: string | null
  ransomware_use: string | null
  has_known_ransomware: number
  notes: string
  cwes: string
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  cvss_severity: string | null
  epss_score: number | null
  assigner: string | null
  date_published: string | null
  date_updated: string | null
  date_updated_ts: number | null
  exploited_since: string | null
  source_url: string | null
  poc_url: string | null
  poc_published_at: string | null
  reference_links: string
  aliases: string
  metasploit_module_path: string | null
  metasploit_module_published_at: string | null
  is_well_known: number
  domain_categories: string
  exploit_layers: string
  vulnerability_categories: string
  internet_exposed: number
  has_source_kev: number
  has_source_enisa: number
  has_source_historic: number
  has_source_metasploit: number
  has_source_poc: number
}

export type CatalogSummaryRow = {
  cve_id: string
  entry_id: string
  sources: string
  vendor: string
  vendor_key: string
  product: string
  product_key: string
  vulnerability_name: string
  description: string
  due_date: string | null
  date_added: string | null
  date_published: string | null
  poc_published_at: string | null
  ransomware_use: string | null
  cvss_score: number | null
  cvss_severity: string | null
  epss_score: number | null
  aliases: string
  domain_categories: string
  exploit_layers: string
  vulnerability_categories: string
  internet_exposed: number
}

const DEFAULT_VENDOR = 'Unknown'
const DEFAULT_PRODUCT = 'Unknown'
const DEFAULT_VULNERABILITY = 'Unknown vulnerability'

const parseJsonArray = (value: string | null): string[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed.filter((item): item is string => typeof item === 'string').map(item => item.trim()).filter(Boolean)
  } catch {
    return []
  }
}

const parseJsonObjectArray = <T>(value: string | null): T[] => {
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

const parseAliasArray = (value: string | null): string[] =>
  parseJsonArray(value).map(alias => alias.toUpperCase())

const normaliseCve = (value: string): string => value.toUpperCase()

const ensureString = (value: string | null | undefined, fallback: string): string => {
  const trimmed = value?.trim()
  return trimmed && trimmed.length ? trimmed : fallback
}

const mergeUniqueStrings = (first: string[], second: string[]): string[] => {
  const seen = new Set<string>()
  const result: string[] = []

  for (const value of [...first, ...second]) {
    const trimmed = value?.trim()
    if (!trimmed || seen.has(trimmed)) {
      continue
    }
    seen.add(trimmed)
    result.push(trimmed)
  }

  return result
}

const mergeUniqueClassification = <T extends string>(first: T[], second: T[]): T[] => {
  const seen = new Set<T>()
  const result: T[] = []

  for (const value of [...first, ...second]) {
    if (!value || seen.has(value)) {
      continue
    }
    seen.add(value)
    result.push(value)
  }

  return result
}

const mergeAffectedProducts = (
  first: KevAffectedProduct[],
  second: KevAffectedProduct[]
): KevAffectedProduct[] => {
  const combined: KevAffectedProduct[] = []
  const map = new Map<string, KevAffectedProduct>()

  for (const product of [...first, ...second]) {
    const key = `${product.vendorKey}::${product.productKey}::${product.source}::${product.status ?? ''}`
    const existing = map.get(key)

    if (!existing) {
      map.set(key, {
        vendor: product.vendor,
        vendorKey: product.vendorKey,
        product: product.product,
        productKey: product.productKey,
        status: product.status ?? null,
        source: product.source,
        platforms: mergeUniqueStrings([], product.platforms),
        versions: product.versions.map(version => ({ ...version }))
      })
      continue
    }

    existing.platforms = mergeUniqueStrings(existing.platforms, product.platforms)

    const seenVersions = new Set(existing.versions.map(version => JSON.stringify(version)))
    for (const version of product.versions) {
      const serialised = JSON.stringify(version)
      if (seenVersions.has(serialised)) {
        continue
      }
      seenVersions.add(serialised)
      existing.versions.push({ ...version })
    }
  }

  map.forEach(value => combined.push(value))
  return combined
}

const mergeProblemTypes = (
  first: KevProblemType[],
  second: KevProblemType[]
): KevProblemType[] => {
  const result: KevProblemType[] = []
  const seen = new Set<string>()

  for (const item of [...first, ...second]) {
    const key = `${item.source}:${item.cweId ?? ''}:${item.description}`.toLowerCase()
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    result.push({ ...item })
  }

  return result
}

const toTimestamp = (value: string | null | undefined): number | null => {
  if (!value) {
    return null
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return null
  }

  return date.getTime()
}

const pickEarliestString = (first: string | null, second: string | null): string | null => {
  const firstTime = toTimestamp(first)
  const secondTime = toTimestamp(second)

  if (firstTime === null) {
    return second ?? null
  }

  if (secondTime === null) {
    return first ?? null
  }

  return firstTime <= secondTime ? first : second
}

const pickLatestString = (first: string | null, second: string | null): string | null => {
  const firstTime = toTimestamp(first)
  const secondTime = toTimestamp(second)

  if (firstTime === null) {
    return second ?? null
  }

  if (secondTime === null) {
    return first ?? null
  }

  return firstTime >= secondTime ? first : second
}

const sortByChronology = (a: KevEntry, b: KevEntry): number => {
  const aTime = toTimestamp(a.dateAdded) ?? Number.NEGATIVE_INFINITY
  const bTime = toTimestamp(b.dateAdded) ?? Number.NEGATIVE_INFINITY

  if (bTime !== aTime) {
    return bTime - aTime
  }

  return a.cveId.localeCompare(b.cveId)
}

const createEmptyCategories = (): EntryCategories => ({
  domain: [],
  exploit: [],
  vulnerability: []
})

const getEntryCategories = (
  entryId: string,
  categories: Map<string, EntryCategories>
): EntryCategories => {
  const existing = categories.get(entryId)
  if (existing) {
    return existing
  }

  const empty = createEmptyCategories()
  categories.set(entryId, empty)
  return empty
}

const toStandardEntry = (
  row: VulnerabilityEntryRow,
  categories: EntryCategories,
  source: 'kev' | 'historic' | 'metasploit' | 'poc'
): KevEntry => {
  const cveId = normaliseCve(row.cve_id ?? row.id)
  const notes = parseJsonArray(row.notes)
  const cwes = parseJsonArray(row.cwes)
  const aliasList = parseAliasArray(row.aliases)
  const normalised = normaliseVendorProduct(
    { vendor: row.vendor, product: row.product },
    undefined,
    undefined,
    {
      vulnerabilityName: row.vulnerability_name,
      description: row.description,
      cveId,
      aliases: aliasList
    }
  )
  const affectedProducts = parseJsonObjectArray<KevAffectedProduct>(row.affected_products)
  const problemTypes = parseJsonObjectArray<KevProblemType>(row.problem_types)
  const vendorKey =
    !row.vendor_key ||
    row.vendor_key === 'unknown' ||
    row.vendor_key === 'vendor-unknown' ||
    !isMeaningfulVendorLabel(row.vendor)
      ? normalised.vendor.key
      : row.vendor_key
  const productKey =
    !row.product_key ||
    row.product_key === 'unknown__unknown' ||
    (row.product_key?.endsWith('__product-unknown') ?? false) ||
    !isMeaningfulProductLabel(row.product)
      ? normalised.product.key
      : row.product_key

  return {
    id: row.id,
    cveId,
    sources: [source],
    vendor: normalised.vendor.label,
    vendorKey,
    product: normalised.product.label,
    productKey,
    vulnerabilityName: ensureString(row.vulnerability_name, cveId || DEFAULT_VULNERABILITY),
    description: row.description ?? '',
    requiredAction: row.required_action ?? null,
    dateAdded: row.date_added ?? '',
    dueDate: row.due_date ?? null,
    ransomwareUse: row.ransomware_use ?? null,
    notes,
    cwes,
    cvssScore: typeof row.cvss_score === 'number' ? row.cvss_score : null,
    cvssVector: row.cvss_vector ?? null,
    cvssVersion: row.cvss_version ?? null,
    cvssSeverity:
      typeof row.cvss_severity === 'string'
        ? (row.cvss_severity as KevEntry['cvssSeverity'])
        : null,
    epssScore: typeof row.epss_score === 'number' ? row.epss_score : null,
    assigner: row.assigner ?? null,
    datePublished: row.date_published ?? row.date_added ?? null,
    dateUpdated: row.updated_at ?? null,
    exploitedSince: row.exploited_since ?? row.date_added ?? null,
    sourceUrl: row.source_url ?? null,
    pocUrl: row.poc_url ?? null,
    pocPublishedAt: row.poc_published_at ?? null,
    references: parseJsonArray(row.reference_links),
    aliases: aliasList.length ? aliasList : [cveId],
    affectedProducts,
    problemTypes,
    metasploitModulePath: row.metasploit_module_path ?? null,
    metasploitModulePublishedAt: row.metasploit_module_published_at ?? null,
    domainCategories: categories.domain as KevEntry['domainCategories'],
    exploitLayers: categories.exploit as KevEntry['exploitLayers'],
    vulnerabilityCategories: categories.vulnerability as KevEntry['vulnerabilityCategories'],
    internetExposed: row.internet_exposed === 1
  }
}

const toKevEntry = (
  row: VulnerabilityEntryRow,
  categories: EntryCategories
): KevEntry => toStandardEntry(row, categories, 'kev')

const toHistoricEntry = (
  row: VulnerabilityEntryRow,
  categories: EntryCategories
): KevEntry => toStandardEntry(row, categories, 'historic')

const toMetasploitEntry = (
  row: VulnerabilityEntryRow,
  categories: EntryCategories
): KevEntry => toStandardEntry(row, categories, 'metasploit')

const toPocEntry = (
  row: VulnerabilityEntryRow,
  categories: EntryCategories
): KevEntry => toStandardEntry(row, categories, 'poc')

const toEnisaEntry = (
  row: VulnerabilityEntryRow,
  categories: EntryCategories
): KevEntry | null => {
  if (!row.cve_id) {
    return null
  }

  const cveId = normaliseCve(row.cve_id)
  const references = parseJsonArray(row.reference_links)
  const aliases = parseAliasArray(row.aliases)
  const normalised = normaliseVendorProduct({ vendor: row.vendor, product: row.product })
  const affectedProducts = parseJsonObjectArray<KevAffectedProduct>(row.affected_products)
  const problemTypes = parseJsonObjectArray<KevProblemType>(row.problem_types)
  const vendorKey = row.vendor_key ?? normalised.vendor.key
  const productKey = row.product_key ?? normalised.product.key

  return {
    id: row.id,
    cveId,
    sources: ['enisa'],
    vendor: normalised.vendor.label,
    vendorKey,
    product: normalised.product.label,
    productKey,
    vulnerabilityName: ensureString(row.vulnerability_name, aliases[0] ?? cveId ?? DEFAULT_VULNERABILITY),
    description: row.description ?? '',
    requiredAction: null,
    dateAdded: row.exploited_since ?? row.date_published ?? '',
    dueDate: null,
    ransomwareUse: null,
    notes: [],
    cwes: [],
    cvssScore: typeof row.cvss_score === 'number' ? row.cvss_score : null,
    cvssVector: row.cvss_vector ?? null,
    cvssVersion: row.cvss_version ?? null,
    cvssSeverity:
      typeof row.cvss_severity === 'string'
        ? (row.cvss_severity as KevEntry['cvssSeverity'])
        : null,
    epssScore: typeof row.epss_score === 'number' ? row.epss_score : null,
    assigner: row.assigner ?? null,
    datePublished: row.date_published ?? null,
    dateUpdated: row.date_updated ?? null,
    exploitedSince: row.exploited_since ?? null,
    sourceUrl: row.source_url ?? null,
    references,
    aliases: aliases.length ? aliases : [cveId],
    affectedProducts,
    problemTypes,
    metasploitModulePath: row.metasploit_module_path ?? null,
    metasploitModulePublishedAt: null,
    domainCategories: categories.domain as KevEntry['domainCategories'],
    exploitLayers: categories.exploit as KevEntry['exploitLayers'],
    vulnerabilityCategories: categories.vulnerability as KevEntry['vulnerabilityCategories'],
    internetExposed: row.internet_exposed === 1
  }
}

const mergeEntry = (existing: KevEntry, incoming: KevEntry): KevEntry => {
  const sources = existing.sources.slice()
  for (const source of incoming.sources) {
    if (!sources.includes(source)) {
      sources.push(source)
    }
  }

  const vendor =
    existing.vendor !== DEFAULT_VENDOR ? existing.vendor : incoming.vendor
  const product =
    existing.product !== DEFAULT_PRODUCT ? existing.product : incoming.product
  const normalised = normaliseVendorProduct({ vendor, product })
  const vulnerabilityName =
    existing.vulnerabilityName !== DEFAULT_VULNERABILITY
      ? existing.vulnerabilityName
      : incoming.vulnerabilityName

  const description =
    existing.description?.length ?? 0 >= (incoming.description?.length ?? 0)
      ? existing.description
      : incoming.description

  const requiredAction = existing.requiredAction ?? incoming.requiredAction ?? null
  const dateAdded = pickEarliestString(existing.dateAdded, incoming.dateAdded) ?? ''
  const dueDate = existing.dueDate ?? incoming.dueDate ?? null
  const ransomwareUse = existing.ransomwareUse ?? incoming.ransomwareUse ?? null
  const notes = mergeUniqueStrings(existing.notes, incoming.notes)
  const cwes = mergeUniqueStrings(existing.cwes, incoming.cwes)

  const cvssScore = existing.cvssScore ?? incoming.cvssScore ?? null
  const cvssVector = existing.cvssVector ?? incoming.cvssVector ?? null
  const cvssVersion = existing.cvssVersion ?? incoming.cvssVersion ?? null
  const cvssSeverity = existing.cvssSeverity ?? incoming.cvssSeverity ?? null

  const epssScore = existing.epssScore ?? incoming.epssScore ?? null
  const assigner = existing.assigner ?? incoming.assigner ?? null

  const datePublished = pickEarliestString(existing.datePublished, incoming.datePublished)
  const dateUpdated = pickLatestString(existing.dateUpdated, incoming.dateUpdated)
  const exploitedSince = pickEarliestString(existing.exploitedSince, incoming.exploitedSince)
  const sourceUrl = existing.sourceUrl ?? incoming.sourceUrl ?? null
  const pocUrl = existing.pocUrl ?? incoming.pocUrl ?? null
  const pocPublishedAt = pickEarliestString(existing.pocPublishedAt, incoming.pocPublishedAt)
  const references = mergeUniqueStrings(existing.references, incoming.references)
  const aliases = mergeUniqueStrings(existing.aliases, incoming.aliases).map(alias => alias.toUpperCase())

  const affectedProducts = mergeAffectedProducts(existing.affectedProducts, incoming.affectedProducts)
  const problemTypes = mergeProblemTypes(existing.problemTypes, incoming.problemTypes)

  const metasploitModulePath = existing.metasploitModulePath ?? incoming.metasploitModulePath ?? null
  const metasploitModulePublishedAt = pickEarliestString(
    existing.metasploitModulePublishedAt,
    incoming.metasploitModulePublishedAt
  )

  const domainCategories = mergeUniqueClassification(
    existing.domainCategories,
    incoming.domainCategories
  ) as KevEntry['domainCategories']

  const exploitLayers = mergeUniqueClassification(
    existing.exploitLayers,
    incoming.exploitLayers
  ) as KevEntry['exploitLayers']

  const vulnerabilityCategories = mergeUniqueClassification(
    existing.vulnerabilityCategories,
    incoming.vulnerabilityCategories
  ) as KevEntry['vulnerabilityCategories']

  return {
    ...existing,
    sources,
    vendor: normalised.vendor.label,
    vendorKey: normalised.vendor.key,
    product: normalised.product.label,
    productKey: normalised.product.key,
    vulnerabilityName,
    description,
    requiredAction,
    dateAdded,
    dueDate,
    ransomwareUse,
    notes,
    cwes,
    cvssScore,
    cvssVector,
    cvssVersion,
    cvssSeverity,
    epssScore,
    assigner,
    datePublished,
    dateUpdated,
    exploitedSince,
    sourceUrl,
    pocUrl,
    pocPublishedAt,
    references,
    aliases,
    affectedProducts,
    problemTypes,
    metasploitModulePath,
    metasploitModulePublishedAt,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed: existing.internetExposed || incoming.internetExposed
  }
}

const buildCatalogEntries = (
  kevEntries: KevEntry[],
  enisaEntries: KevEntry[],
  historicEntries: KevEntry[],
  metasploitEntries: KevEntry[],
  pocEntries: KevEntry[]
): KevEntry[] => {
  const merged = new Map<string, KevEntry>()

  const add = (entry: KevEntry) => {
    const key = entry.cveId.toUpperCase()
    const existing = merged.get(key)
    if (!existing) {
      merged.set(key, {
        ...entry,
        id: `catalog:${key}`,
        cveId: key,
        aliases: mergeUniqueStrings(entry.aliases, [key]).map(alias => alias.toUpperCase())
      })
      return
    }

    merged.set(key, mergeEntry(existing, entry))
  }

  kevEntries.forEach(add)
  enisaEntries.forEach(add)
  historicEntries.forEach(add)
  metasploitEntries.forEach(add)
  pocEntries.forEach(add)

  const entries = Array.from(merged.values())
  entries.sort(sortByChronology)
  return entries
}

const toDimensionTuples = (
  entry: KevEntry,
  dimension: CatalogDimension
): Array<{ value: string; name: string }> => {
  switch (dimension) {
    case 'domain':
      return entry.domainCategories.map(value => ({ value, name: value }))
    case 'exploit':
      return entry.exploitLayers.map(value => ({ value, name: value }))
    case 'vulnerability':
      return entry.vulnerabilityCategories.map(value => ({ value, name: value }))
    default:
      return []
  }
}

const toJson = (value: unknown): string => JSON.stringify(value ?? [])

const toYear = (timestamp: number | null): number | null => {
  if (timestamp === null) {
    return null
  }
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return null
  }
  return date.getUTCFullYear()
}

const extractBounds = (
  entries: KevEntry[]
): { earliest: string | null; latest: string | null } => {
  let earliest: { ts: number; value: string } | null = null
  let latest: { ts: number; value: string } | null = null

  for (const entry of entries) {
    if (!entry.dateAdded) {
      continue
    }
    const timestamp = toTimestamp(entry.dateAdded)
    if (timestamp === null) {
      continue
    }

    if (!earliest || timestamp < earliest.ts) {
      earliest = { ts: timestamp, value: entry.dateAdded }
    }
    if (!latest || timestamp > latest.ts) {
      latest = { ts: timestamp, value: entry.dateAdded }
    }
  }

  return {
    earliest: earliest?.value ?? null,
    latest: latest?.value ?? null
  }
}

const toBooleanFlag = (value: boolean): number => (value ? 1 : 0)

const toKnownRansomwareFlag = (value: string | null): number =>
  value?.toLowerCase().includes('known') ? 1 : 0

export const rebuildCatalog = async (
  db: DrizzleDatabase,
  options: RebuildCatalogOptions = {},
): Promise<KevEntrySummary> => {
  const entryRows = await db.all(
    sql<VulnerabilityEntryRow>`
      SELECT
        id,
        cve_id,
        source,
        vendor,
        product,
        vendor_key,
        product_key,
        vulnerability_name,
        description,
        required_action,
        date_added,
        due_date,
        ransomware_use,
        notes,
        cwes,
        cvss_score,
        cvss_vector,
        cvss_version,
        cvss_severity,
        epss_score,
        assigner,
        date_published,
        date_updated,
        exploited_since,
        source_url,
        poc_url,
        poc_published_at,
        reference_links,
        aliases,
        affected_products,
        problem_types,
        metasploit_module_path,
        metasploit_module_published_at,
        internet_exposed,
        updated_at
      FROM ${tables.vulnerabilityEntries}
    `
  )

  const categoryRows = await db.all(
    sql<EntryCategoryRow>`
      SELECT entry_id, category_type, value, name FROM ${tables.vulnerabilityEntryCategories}
    `
  )

  const categoryMap = new Map<string, EntryCategories>()

  for (const row of categoryRows) {
    const target = getEntryCategories(row.entry_id, categoryMap)
    const value = row.name?.trim() || row.value?.trim()
    if (!value) {
      continue
    }

    const targetList =
      row.category_type === 'domain'
        ? target.domain
        : row.category_type === 'exploit'
          ? target.exploit
          : row.category_type === 'vulnerability'
            ? target.vulnerability
            : null

    if (!targetList) {
      continue
    }

    if (!targetList.includes(value)) {
      targetList.push(value as string)
    }
  }

  const kevEntries = entryRows
    .filter(row => row.source === 'kev')
    .map(row => toKevEntry(row, getEntryCategories(row.id, categoryMap)))

  const enisaEntries = entryRows
    .filter(row => row.source === 'enisa')
    .map(row => toEnisaEntry(row, getEntryCategories(row.id, categoryMap)))
    .filter((entry): entry is KevEntry => entry !== null)

  const historicEntries = entryRows
    .filter(row => row.source === 'historic')
    .map(row => toHistoricEntry(row, getEntryCategories(row.id, categoryMap)))

  const metasploitEntries = entryRows
    .filter(row => row.source === 'metasploit')
    .map(row => toMetasploitEntry(row, getEntryCategories(row.id, categoryMap)))

  const pocEntries = entryRows
    .filter(row => row.source === 'poc')
    .map(row => toPocEntry(row, getEntryCategories(row.id, categoryMap)))

  const catalogEntries = buildCatalogEntries(
    kevEntries,
    enisaEntries,
    historicEntries,
    metasploitEntries,
    pocEntries
  )

  options.onStart?.(catalogEntries.length)

  await db.transaction(tx => {
    const existingRows = tx
      .select({ cveId: tables.catalogEntries.cveId })
      .from(tables.catalogEntries)
      .all()
    const existingIds = new Set(existingRows.map(row => row.cveId))
    const nextIds = new Set<string>()
    const progressTotal = catalogEntries.length

    const upsertCatalogEntry = (entry: CatalogEntryRow) => {
      const dateAddedTs = toTimestamp(entry.dateAdded)
      const dateUpdatedTs = toTimestamp(entry.dateUpdated)
      const isWellKnown = lookupCveName(entry.cveId) ? 1 : 0
      const hasKnownRansomware = toKnownRansomwareFlag(entry.ransomwareUse ?? null)
      const hasSourceKev = toBooleanFlag(entry.sources.includes('kev'))
      const hasSourceEnisa = toBooleanFlag(entry.sources.includes('enisa'))
      const hasSourceHistoric = toBooleanFlag(entry.sources.includes('historic'))
      const hasSourceMetasploit = toBooleanFlag(entry.sources.includes('metasploit'))
      const hasSourcePoc = toBooleanFlag(entry.sources.includes('poc'))

      const record = {
        entryId: entry.id,
        sources: toJson(entry.sources),
        vendor: entry.vendor,
        vendorKey: entry.vendorKey,
        product: entry.product,
        productKey: entry.productKey,
        vulnerabilityName: entry.vulnerabilityName,
        description: entry.description,
        requiredAction: entry.requiredAction,
        dateAdded: entry.dateAdded,
        dateAddedTs,
        dateAddedYear: toYear(dateAddedTs),
        dueDate: entry.dueDate,
        ransomwareUse: entry.ransomwareUse,
        hasKnownRansomware,
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
        dateUpdatedTs,
        exploitedSince: entry.exploitedSince,
        sourceUrl: entry.sourceUrl,
        pocUrl: entry.pocUrl,
        pocPublishedAt: entry.pocPublishedAt,
        referenceLinks: toJson(entry.references),
        aliases: toJson(entry.aliases),
        metasploitModulePath: entry.metasploitModulePath,
        metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
        isWellKnown,
        domainCategories: toJson(entry.domainCategories),
        exploitLayers: toJson(entry.exploitLayers),
        vulnerabilityCategories: toJson(entry.vulnerabilityCategories),
        internetExposed: toBooleanFlag(entry.internetExposed),
        hasSourceKev,
        hasSourceEnisa,
        hasSourceHistoric,
        hasSourceMetasploit,
        hasSourcePoc
      }

      tx
        .insert(tables.catalogEntries)
        .values({ cveId: entry.cveId, ...record })
        .onConflictDoUpdate({
          target: tables.catalogEntries.cveId,
          set: record
        })
        .run()

      tx
        .delete(tables.catalogEntryDimensions)
        .where(eq(tables.catalogEntryDimensions.cveId, entry.cveId))
        .run()

      const dimensions: CatalogDimension[] = ['domain', 'exploit', 'vulnerability']
      const dimensionRecords: Array<{ cveId: string; dimension: string; value: string; name: string }> = []

      for (const dimension of dimensions) {
        const tuples = toDimensionTuples(entry, dimension)
        for (const tuple of tuples) {
          if (!tuple.value || tuple.name === 'Other') {
            continue
          }
          dimensionRecords.push({
            cveId: entry.cveId,
            dimension,
            value: tuple.value,
            name: tuple.name
          })
        }
      }

      if (dimensionRecords.length) {
        tx.insert(tables.catalogEntryDimensions).values(dimensionRecords).run()
      }

      tx
        .delete(tables.catalogEntriesFts)
        .where(eq(tables.catalogEntriesFts.cveId, entry.cveId))
        .run()

      tx
        .insert(tables.catalogEntriesFts)
        .values({
          cveId: entry.cveId,
          vendor: entry.vendor,
          product: entry.product,
          vulnerabilityName: entry.vulnerabilityName,
          description: entry.description,
          aliases: entry.aliases.join(' ')
        })
        .run()
    }

    for (let index = 0; index < catalogEntries.length; index += 1) {
      const entry = catalogEntries[index]
      nextIds.add(entry.cveId)
      upsertCatalogEntry(entry)

      if ((index + 1) % 25 === 0 || index + 1 === progressTotal) {
        options.onProgress?.(index + 1, progressTotal)
      }
    }

    const staleIds: string[] = []
    for (const existingId of existingIds) {
      if (!nextIds.has(existingId)) {
        staleIds.push(existingId)
      }
    }

    if (staleIds.length > 0) {
      const chunkSize = 100
      for (let offset = 0; offset < staleIds.length; offset += chunkSize) {
        const chunk = staleIds.slice(offset, offset + chunkSize)
        tx
          .delete(tables.catalogEntries)
          .where(inArray(tables.catalogEntries.cveId, chunk))
          .run()
        tx
          .delete(tables.catalogEntryDimensions)
          .where(inArray(tables.catalogEntryDimensions.cveId, chunk))
          .run()
        tx
          .delete(tables.catalogEntriesFts)
          .where(inArray(tables.catalogEntriesFts.cveId, chunk))
          .run()
      }
    }
  })

  options.onComplete?.(catalogEntries.length)

  const bounds = extractBounds(catalogEntries)

  await Promise.all([
    setMetadataValue('catalog.entryCount', String(catalogEntries.length)),
    setMetadataValue('catalog.earliestDate', bounds.earliest ?? ''),
    setMetadataValue('catalog.latestDate', bounds.latest ?? '')
  ])

  return {
    count: catalogEntries.length,
    earliest: bounds.earliest,
    latest: bounds.latest
  }
}

const parseJsonStringArray = (value: string): string[] => {
  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed.filter((item): item is string => typeof item === 'string')
  } catch {
    return []
  }
}

const toProgramType = (value: string | null | undefined): MarketProgramType => {
  if (value === 'exploit-broker' || value === 'bug-bounty') {
    return value
  }
  return 'other'
}

const SQLITE_MAX_VARIABLE_NUMBER = 999

const chunkArray = <T>(items: T[], size: number): T[][] => {
  if (size <= 0) {
    return [items]
  }

  const chunks: T[][] = []
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size))
  }
  return chunks
}

const createEmptyMarketSignal = (): MarketSignal => ({
  offerCount: 0,
  minRewardUsd: null,
  maxRewardUsd: null,
  averageRewardUsd: null,
  lastSeenAt: null,
  programTypes: [],
  categories: []
})

export const getMarketSignalsForProducts = async (
  db: DrizzleDatabase,
  productKeys: string[],
  options: { programTypes?: MarketProgramType[] } = {}
): Promise<Map<string, MarketSignal>> => {
  const keys = Array.from(new Set(productKeys.filter(key => Boolean(key))))
  const signals = new Map<string, MarketSignal>()

  if (!keys.length) {
    return signals
  }

  const target = tables.marketOfferTargets
  const offer = tables.marketOffers
  const program = tables.marketPrograms
  const category = tables.marketOfferCategories

  const programTypeFilter = Array.from(
    new Set(
      (options.programTypes ?? []).filter(
        (type): type is MarketProgramType =>
          type === 'exploit-broker' || type === 'bug-bounty' || type === 'other'
      )
    )
  )

  const extraVariableCount = programTypeFilter.length
  const productKeyChunkSize = Math.max(
    1,
    SQLITE_MAX_VARIABLE_NUMBER - Math.max(extraVariableCount, 1)
  )
  const productKeyChunks = chunkArray(keys, productKeyChunkSize)
  const programCondition =
    programTypeFilter.length > 0 ? inArray(program.programType, programTypeFilter) : null

  const priceRows: Array<{
    productKey: string
    minReward: number | null
    maxReward: number | null
    averageReward: number | null
    lastSeenAt: string | null
    offerCount: number
    programTypes: string | null
  }> = []

  for (const chunk of productKeyChunks) {
    const productCondition = inArray(target.productKey, chunk)
    const rows = await db
      .select({
        productKey: target.productKey,
        minReward: sql<number | null>`min(COALESCE(${offer.minRewardUsd}, ${offer.maxRewardUsd}))`,
        maxReward: sql<number | null>`max(COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd}))`,
        averageReward: sql<number | null>`avg((COALESCE(${offer.minRewardUsd}, ${offer.maxRewardUsd}) + COALESCE(${offer.maxRewardUsd}, ${offer.minRewardUsd})) / 2.0)`,
        lastSeenAt: sql<string | null>`max(${offer.sourceCaptureDate})`,
        offerCount: sql<number>`count(distinct ${offer.id})`,
        programTypes: sql<string | null>`json_group_array(distinct ${program.programType})`
      })
      .from(target)
      .innerJoin(offer, eq(offer.id, target.offerId))
      .innerJoin(program, eq(program.id, offer.programId))
      .where(programCondition ? and(productCondition, programCondition) : productCondition)
      .groupBy(target.productKey)
      .all()

    priceRows.push(...rows)
  }

  for (const row of priceRows) {
    const programTypeValues = typeof row.programTypes === 'string'
      ? parseJsonStringArray(row.programTypes)
      : []
    const programTypes = Array.from(
      new Set(programTypeValues.map(type => toProgramType(type)))
    )

    signals.set(row.productKey, {
      offerCount: Number(row.offerCount ?? 0),
      minRewardUsd:
        typeof row.minReward === 'number' && Number.isFinite(row.minReward)
          ? row.minReward
          : null,
      maxRewardUsd:
        typeof row.maxReward === 'number' && Number.isFinite(row.maxReward)
          ? row.maxReward
          : null,
      averageRewardUsd:
        typeof row.averageReward === 'number' && Number.isFinite(row.averageReward)
          ? row.averageReward
          : null,
      lastSeenAt: row.lastSeenAt ?? null,
      programTypes,
      categories: []
    })
  }

  const categoryRows: Array<{
    productKey: string
    categoryType: string
    categoryKey: string
    categoryName: string
  }> = []

  for (const chunk of productKeyChunks) {
    const productCondition = inArray(target.productKey, chunk)
    const rows = await db
      .select({
        productKey: target.productKey,
        categoryType: category.categoryType,
        categoryKey: category.categoryKey,
        categoryName: category.categoryName
      })
      .from(target)
      .innerJoin(offer, eq(offer.id, target.offerId))
      .innerJoin(category, eq(category.offerId, offer.id))
      .innerJoin(program, eq(program.id, offer.programId))
      .where(programCondition ? and(productCondition, programCondition) : productCondition)
      .groupBy(
        target.productKey,
        category.categoryType,
        category.categoryKey,
        category.categoryName
      )
      .all()

    categoryRows.push(...rows)
  }

  for (const row of categoryRows) {
    const existing = signals.get(row.productKey) ?? createEmptyMarketSignal()
    if (!signals.has(row.productKey)) {
      signals.set(row.productKey, existing)
    }

    const exists = existing.categories.some(
      categoryItem =>
        categoryItem.type === row.categoryType && categoryItem.name === row.categoryName
    )

    if (!exists) {
      existing.categories.push({
        type: row.categoryType,
        name: row.categoryName
      })
    }
  }

  return signals
}

export const catalogRowToEntry = (
  row: CatalogEntryRow,
  options?: { marketSignals?: Map<string, MarketSignal> }
): KevEntry => {
  const sources = parseJsonStringArray(row.sources) as CatalogSource[]
  const notes = parseJsonStringArray(row.notes)
  const cwes = parseJsonStringArray(row.cwes)
  const references = parseJsonStringArray(row.reference_links)
  const aliases = parseJsonStringArray(row.aliases)
  const domainCategories = parseJsonStringArray(row.domain_categories) as KevEntry['domainCategories']
  const exploitLayers = parseJsonStringArray(row.exploit_layers) as KevEntry['exploitLayers']
  const vulnerabilityCategories = parseJsonStringArray(row.vulnerability_categories) as KevEntry['vulnerabilityCategories']

  const marketSignals = options?.marketSignals?.get(row.product_key) ?? null

  return {
    id: row.entry_id,
    cveId: row.cve_id,
    sources,
    vendor: row.vendor,
    vendorKey: row.vendor_key,
    product: row.product,
    productKey: row.product_key,
    affectedProducts: [],
    problemTypes: [],
    vulnerabilityName: row.vulnerability_name,
    description: row.description,
    requiredAction: row.required_action,
    dateAdded: row.date_added ?? '',
    dueDate: row.due_date,
    ransomwareUse: row.ransomware_use,
    notes,
    cwes,
    cvssScore: typeof row.cvss_score === 'number' ? row.cvss_score : null,
    cvssVector: row.cvss_vector,
    cvssVersion: row.cvss_version,
    cvssSeverity:
      typeof row.cvss_severity === 'string'
        ? (row.cvss_severity as KevEntry['cvssSeverity'])
        : null,
    epssScore: typeof row.epss_score === 'number' ? row.epss_score : null,
    assigner: row.assigner,
    datePublished: row.date_published,
    dateUpdated: row.date_updated,
    exploitedSince: row.exploited_since,
    sourceUrl: row.source_url,
    pocUrl: row.poc_url,
    pocPublishedAt: row.poc_published_at,
    references,
    aliases,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed: row.internet_exposed === 1,
    metasploitModulePath: row.metasploit_module_path,
    metasploitModulePublishedAt: row.metasploit_module_published_at,
    marketSignals
  }
}

export const catalogRowToSummary = (
  row: CatalogSummaryRow,
  options?: { marketSignals?: Map<string, MarketSignal> }
): KevEntrySummary => {
  const sources = parseJsonStringArray(row.sources) as CatalogSource[]
  const aliases = parseJsonStringArray(row.aliases)
  const domainCategories = parseJsonStringArray(
    row.domain_categories
  ) as KevEntrySummary['domainCategories']
  const exploitLayers = parseJsonStringArray(
    row.exploit_layers
  ) as KevEntrySummary['exploitLayers']
  const vulnerabilityCategories = parseJsonStringArray(
    row.vulnerability_categories
  ) as KevEntrySummary['vulnerabilityCategories']

  const marketSignals = options?.marketSignals?.get(row.product_key) ?? null

  return {
    id: row.entry_id,
    cveId: row.cve_id,
    sources,
    vendor: row.vendor,
    vendorKey: row.vendor_key,
    product: row.product,
    productKey: row.product_key,
    vulnerabilityName: row.vulnerability_name,
    description: row.description,
    dueDate: row.due_date ?? null,
    dateAdded: row.date_added ?? '',
    datePublished: row.date_published ?? null,
    pocPublishedAt: row.poc_published_at ?? null,
    ransomwareUse: row.ransomware_use,
    cvssScore: typeof row.cvss_score === 'number' ? row.cvss_score : null,
    cvssSeverity:
      typeof row.cvss_severity === 'string'
        ? (row.cvss_severity as KevEntrySummary['cvssSeverity'])
        : null,
    epssScore: typeof row.epss_score === 'number' ? row.epss_score : null,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed: row.internet_exposed === 1,
    aliases: aliases.length ? aliases : [row.cve_id],
    marketSignals
  }
}
