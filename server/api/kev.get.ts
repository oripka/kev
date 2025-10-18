import { getQuery } from 'h3'
import { lookupCveName } from '~/utils/cveToNameMap'
import type {
  KevCountDatum,
  KevDomainCategory,
  KevEntry,
  KevExploitLayer,
  KevResponse,
  KevVulnerabilityCategory
} from '~/types'
import { getDatabase, getMetadata } from '../utils/sqlite'

type KevRow = {
  cve_id: string
  vendor: string
  product: string
  vulnerability_name: string
  description: string
  required_action: string
  date_added: string
  due_date: string | null
  ransomware_use: string | null
  notes: string | null
  cwes: string | null
  domain_categories: string | null
  exploit_layers: string | null
  vulnerability_categories: string | null
}

type KevQuery = {
  search?: string
  vendor?: string
  product?: string
  domain?: KevDomainCategory
  exploit?: KevExploitLayer
  vulnerability?: KevVulnerabilityCategory
  startYear?: number
  endYear?: number
  wellKnownOnly?: boolean
}

const parseJsonArray = (value: string | null): string[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    return Array.isArray(parsed) ? (parsed.filter(item => typeof item === 'string') as string[]) : []
  } catch {
    return []
  }
}

const toEntries = (rows: KevRow[]): KevEntry[] =>
  rows.map(row => ({
    cveId: row.cve_id,
    vendor: row.vendor,
    product: row.product,
    vulnerabilityName: row.vulnerability_name,
    description: row.description,
    requiredAction: row.required_action,
    dateAdded: row.date_added,
    dueDate: row.due_date,
    ransomwareUse: row.ransomware_use,
    notes: parseJsonArray(row.notes),
    cwes: parseJsonArray(row.cwes),
    domainCategories: parseJsonArray(row.domain_categories) as KevEntry['domainCategories'],
    exploitLayers: parseJsonArray(row.exploit_layers) as KevEntry['exploitLayers'],
    vulnerabilityCategories: parseJsonArray(row.vulnerability_categories) as KevEntry['vulnerabilityCategories']
  }))

const escapeLikePattern = (value: string) => value.replace(/[%_\\]/g, '\\$&')

const aggregateCounts = (
  entries: KevEntry[],
  accessor: (entry: KevEntry) => string | string[]
): KevCountDatum[] => {
  const totals = new Map<string, number>()

  for (const entry of entries) {
    const raw = accessor(entry)
    const values = Array.isArray(raw) ? raw : [raw]

    for (const value of values) {
      if (!value || value === 'Other') {
        continue
      }
      totals.set(value, (totals.get(value) ?? 0) + 1)
    }
  }

  return Array.from(totals.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => {
      if (b.count === a.count) {
        return a.name.localeCompare(b.name)
      }
      return b.count - a.count
    })
}

const normaliseQuery = (raw: Record<string, unknown>): KevQuery => {
  const getString = (key: string): string | undefined => {
    const value = raw[key]
    return typeof value === 'string' && value.trim() ? value.trim() : undefined
  }

  const getNumber = (key: string): number | undefined => {
    const value = raw[key]
    if (typeof value === 'string' && value.trim()) {
      const parsed = Number.parseInt(value, 10)
      return Number.isNaN(parsed) ? undefined : parsed
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return Math.trunc(value)
    }
    return undefined
  }

  const filters: KevQuery = {}

  const search = getString('search')
  if (search) {
    filters.search = search
  }

  const vendor = getString('vendor')
  if (vendor) {
    filters.vendor = vendor
  }

  const product = getString('product')
  if (product) {
    filters.product = product
  }

  const domain = getString('domain') as KevDomainCategory | undefined
  if (domain) {
    filters.domain = domain
  }

  const exploit = getString('exploit') as KevExploitLayer | undefined
  if (exploit) {
    filters.exploit = exploit
  }

  const vulnerability = getString('vulnerability') as KevVulnerabilityCategory | undefined
  if (vulnerability) {
    filters.vulnerability = vulnerability
  }

  const startYear = getNumber('startYear')
  const endYear = getNumber('endYear')
  if (typeof startYear === 'number' && typeof endYear === 'number') {
    filters.startYear = startYear
    filters.endYear = endYear
  }

  const wellKnownOnly = raw['wellKnownOnly']
  if (wellKnownOnly === 'true' || wellKnownOnly === '1' || wellKnownOnly === true) {
    filters.wellKnownOnly = true
  }

  return filters
}

const buildQuery = (filters: KevQuery) => {
  const conditions: string[] = []
  const parameters: Record<string, unknown> = {}

  if (filters.vendor) {
    conditions.push('vendor = @vendor')
    parameters.vendor = filters.vendor
  }

  if (filters.product) {
    conditions.push('product = @product')
    parameters.product = filters.product
  }

  if (filters.domain) {
    conditions.push(
      `EXISTS (SELECT 1 FROM json_each(domain_categories) WHERE value = @domain)`
    )
    parameters.domain = filters.domain
  }

  if (filters.exploit) {
    conditions.push(
      `EXISTS (SELECT 1 FROM json_each(exploit_layers) WHERE value = @exploit)`
    )
    parameters.exploit = filters.exploit
  }

  if (filters.vulnerability) {
    conditions.push(
      `EXISTS (SELECT 1 FROM json_each(vulnerability_categories) WHERE value = @vulnerability)`
    )
    parameters.vulnerability = filters.vulnerability
  }

  if (filters.search) {
    conditions.push(
      `LOWER(cve_id || ' ' || vendor || ' ' || product || ' ' || vulnerability_name || ' ' || COALESCE(description, '')) LIKE @search ESCAPE '\\'`
    )
    parameters.search = `%${escapeLikePattern(filters.search.toLowerCase())}%`
  }

  if (typeof filters.startYear === 'number' && typeof filters.endYear === 'number') {
    conditions.push(
      `(date_added IS NULL OR date_added = '' OR (CAST(substr(date_added, 1, 4) AS INTEGER) BETWEEN @startYear AND @endYear))`
    )
    parameters.startYear = filters.startYear
    parameters.endYear = filters.endYear
  }

  let sql = `SELECT
    cve_id,
    vendor,
    product,
    vulnerability_name,
    description,
    required_action,
    date_added,
    due_date,
    ransomware_use,
    notes,
    cwes,
    domain_categories,
    exploit_layers,
    vulnerability_categories
  FROM kev_entries`

  if (conditions.length) {
    sql += `\nWHERE ${conditions.join('\n  AND ')}`
  }

  sql += '\nORDER BY date(date_added) DESC, cve_id ASC'

  return { sql, parameters }
}

const executeQuery = (db: ReturnType<typeof getDatabase>, filters: KevQuery): KevEntry[] => {
  const { sql, parameters } = buildQuery(filters)
  const rows = db.prepare<KevRow>(sql).all(parameters)
  let entries = toEntries(rows)

  if (filters.wellKnownOnly) {
    entries = entries.filter(entry => Boolean(lookupCveName(entry.cveId)))
  }

  return entries
}

const omitFilters = (filters: KevQuery, keys: Array<keyof KevQuery>): KevQuery => {
  const next: KevQuery = {}
  for (const key of Object.keys(filters) as Array<keyof KevQuery>) {
    if (keys.includes(key)) {
      continue
    }
    const value = filters[key]
    if (value !== undefined) {
      next[key] = value
    }
  }
  return next
}

export default defineEventHandler(async (event): Promise<KevResponse> => {
  const db = getDatabase()
  const filters = normaliseQuery(getQuery(event))

  const entries = executeQuery(db, filters)

  const domainEntries = executeQuery(
    db,
    omitFilters(filters, ['domain', 'exploit', 'vulnerability', 'vendor', 'product'])
  )
  const exploitEntries = executeQuery(
    db,
    omitFilters(filters, ['exploit', 'vulnerability', 'vendor', 'product'])
  )
  const vulnerabilityEntries = executeQuery(
    db,
    omitFilters(filters, ['vulnerability', 'vendor', 'product'])
  )
  const vendorEntries = executeQuery(
    db,
    omitFilters(filters, ['vendor', 'product'])
  )
  const productEntries = executeQuery(db, omitFilters(filters, ['product']))

  const counts = {
    domain: aggregateCounts(domainEntries, entry => entry.domainCategories),
    exploit: aggregateCounts(exploitEntries, entry => entry.exploitLayers),
    vulnerability: aggregateCounts(
      vulnerabilityEntries,
      entry => entry.vulnerabilityCategories
    ),
    vendor: aggregateCounts(vendorEntries, entry => entry.vendor),
    product: aggregateCounts(productEntries, entry => entry.product)
  }

  const boundsRow = db
    .prepare<{ earliest: string | null; latest: string | null }>(
      `SELECT
        MIN(NULLIF(date_added, '')) AS earliest,
        MAX(NULLIF(date_added, '')) AS latest
      FROM kev_entries
      WHERE date_added IS NOT NULL AND date_added != ''`
    )
    .get()

  const catalogBounds = {
    earliest: boundsRow?.earliest ?? null,
    latest: boundsRow?.latest ?? null
  }

  const feedUpdatedAt = getMetadata('dateReleased')
  const lastImportAt = getMetadata('lastImportAt')
  const fallbackTimestamp = entries.length > 0 ? new Date().toISOString() : ''

  return {
    updatedAt: feedUpdatedAt ?? lastImportAt ?? fallbackTimestamp,
    entries,
    counts,
    catalogBounds
  }
})
