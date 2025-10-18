import { ofetch } from 'ofetch'
import type { Database as SqliteDatabase } from 'better-sqlite3'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry, KevEntry } from '~/types'
import { setMetadata } from './sqlite'
import { setImportPhase } from './import-progress'

type EnisaApiProduct = {
  product?: {
    name?: string | null
  } | null
  product_version?: string | null
}

type EnisaApiVendor = {
  vendor?: {
    name?: string | null
  } | null
}

type EnisaApiItem = {
  id: string
  enisaUuid?: string | null
  description?: string | null
  datePublished?: string | null
  dateUpdated?: string | null
  baseScore?: number | string | null
  baseScoreVersion?: string | null
  baseScoreVector?: string | null
  references?: string | null
  aliases?: string | null
  assigner?: string | null
  epss?: number | string | null
  exploitedSince?: string | null
  enisaIdProduct?: EnisaApiProduct[] | null
  enisaIdVendor?: EnisaApiVendor[] | null
}

type EnisaApiResponse = {
  items: EnisaApiItem[]
  total: number
}

const ENISA_ENDPOINT = 'https://euvdservices.enisa.europa.eu/api/search'
const PAGE_SIZE = 100

const splitLines = (value?: string | null): string[] =>
  (value ?? '')
    .split('\n')
    .map(entry => entry.trim())
    .filter(Boolean)

const extractCveId = (aliases: string[]): string | null => {
  for (const alias of aliases) {
    const match = alias.match(/CVE-\d{4}-\d+/i)
    if (match) {
      return match[0].toUpperCase()
    }
  }
  return null
}

const parseDate = (value?: string | null): string | null => {
  if (!value) {
    return null
  }

  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return null
  }

  return parsed.toISOString()
}

const normaliseNumber = (value: unknown): number | null => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number.parseFloat(value.trim())
    return Number.isNaN(parsed) ? null : parsed
  }
  return null
}

const toCvssSeverity = (score: number | null): KevEntry['cvssSeverity'] => {
  if (typeof score !== 'number' || Number.isNaN(score)) {
    return null
  }

  if (score <= 0) {
    return 'None'
  }
  if (score < 4) {
    return 'Low'
  }
  if (score < 7) {
    return 'Medium'
  }
  if (score < 9) {
    return 'High'
  }
  return 'Critical'
}

const toProductLabel = (product: EnisaApiProduct | undefined): string => {
  const name = product?.product?.name?.trim()
  const version = product?.product_version?.trim()

  if (name && version) {
    return `${name} ${version}`
  }

  if (name) {
    return name
  }

  return 'Unknown'
}

const toVendorLabel = (vendor: EnisaApiVendor | undefined): string => {
  return vendor?.vendor?.name?.trim() || 'Unknown'
}

const toBaseEntry = (item: EnisaApiItem): KevBaseEntry | null => {
  const aliases = splitLines(item.aliases)
  const cveId = extractCveId(aliases)
  if (!cveId) {
    return null
  }

  const vendor = toVendorLabel(item.enisaIdVendor?.[0])
  const product = toProductLabel(item.enisaIdProduct?.[0])

  const exploitedSince = parseDate(item.exploitedSince)
  const datePublished = parseDate(item.datePublished)
  const dateUpdated = parseDate(item.dateUpdated)

  const cvssScore = normaliseNumber(item.baseScore)
  const epssScore = normaliseNumber(item.epss)

  const references = splitLines(item.references)
  const sourceUrl = references[0] ?? null

  const dateAdded = exploitedSince ?? datePublished ?? ''

  const uniqueId = item.id?.trim() || item.enisaUuid?.trim() || cveId
  if (!uniqueId) {
    return null
  }

  const baseEntry: KevBaseEntry = {
    id: `enisa:${uniqueId}`,
    sources: ['enisa'],
    cveId,
    vendor,
    product,
    vulnerabilityName: aliases[0] ?? item.id,
    description: item.description?.trim() ?? '',
    requiredAction: null,
    dateAdded,
    dueDate: null,
    ransomwareUse: null,
    notes: [],
    cwes: [],
    cvssScore,
    cvssVector: item.baseScoreVector ?? null,
    cvssVersion: item.baseScoreVersion ?? null,
    cvssSeverity: toCvssSeverity(cvssScore),
    epssScore,
    assigner: item.assigner?.trim() ?? null,
    datePublished,
    dateUpdated,
    exploitedSince,
    sourceUrl,
    references,
    aliases
  }

  return baseEntry
}

const toJson = (value: unknown[] | undefined): string => JSON.stringify(value ?? [])

const fetchPage = async (page: number, size: number): Promise<EnisaApiResponse> => {
  return ofetch<EnisaApiResponse>(ENISA_ENDPOINT, {
    query: {
      exploited: 'true',
      fromScore: '0',
      toScore: '10',
      page: String(page),
      size: String(size)
    }
  })
}

export const importEnisaCatalog = async (
  db: SqliteDatabase
): Promise<{ imported: number; lastUpdated: string | null }> => {
  setImportPhase('fetchingEnisa', {
    message: 'Fetching exploited ENISA vulnerabilities',
    completed: 0,
    total: 0
  })

  let page = 0
  const items: EnisaApiItem[] = []
  let total = 0

  // Fetch paginated results
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const response = await fetchPage(page, PAGE_SIZE)

    if (page === 0) {
      total = response.total
    }

    items.push(...response.items)

    setImportPhase('fetchingEnisa', {
      message: `Fetching exploited ENISA vulnerabilities (${Math.min(items.length, total)} of ${total})`,
      completed: Math.min(items.length, total),
      total
    })

    if (items.length >= total || response.items.length === 0) {
      break
    }

    page += 1
  }

  const entryById = new Map<string, KevBaseEntry>()

  for (const item of items) {
    const baseEntry = toBaseEntry(item)
    if (!baseEntry) {
      continue
    }

    if (entryById.has(baseEntry.id)) {
      continue
    }

    entryById.set(baseEntry.id, baseEntry)
  }

  const baseEntries = Array.from(entryById.values())

  setImportPhase('enriching', {
    message: 'Enriching ENISA entries with classification data'
  })

  const entries = baseEntries.map(enrichEntry)

  setImportPhase('savingEnisa', {
    message: 'Saving ENISA entries to the local cache',
    completed: 0,
    total: entries.length
  })

  const deleteEntries = db.prepare('DELETE FROM enisa_entries')
  const insertEntry = db.prepare(
    `INSERT INTO enisa_entries (
      enisa_id,
      cve_id,
      vendor,
      product,
      vulnerability_name,
      description,
      assigner,
      date_published,
      date_updated,
      exploited_since,
      cvss_score,
      cvss_vector,
      cvss_version,
      cvss_severity,
      epss_score,
      reference_links,
      aliases,
      domain_categories,
      exploit_layers,
      vulnerability_categories,
      source_url,
      updated_at
    ) VALUES (
      @enisa_id,
      @cve_id,
      @vendor,
      @product,
      @vulnerability_name,
      @description,
      @assigner,
      @date_published,
      @date_updated,
      @exploited_since,
      @cvss_score,
      @cvss_vector,
      @cvss_version,
      @cvss_severity,
      @epss_score,
      @reference_links,
      @aliases,
      @domain_categories,
      @exploit_layers,
      @vulnerability_categories,
      @source_url,
      CURRENT_TIMESTAMP
    )`
  )

  const transaction = db.transaction((itemsToSave: KevEntry[]) => {
    deleteEntries.run()

    for (let index = 0; index < itemsToSave.length; index += 1) {
      const entry = itemsToSave[index]
      insertEntry.run({
        enisa_id: entry.id,
        cve_id: entry.cveId,
        vendor: entry.vendor,
        product: entry.product,
        vulnerability_name: entry.vulnerabilityName,
        description: entry.description,
        assigner: entry.assigner,
        date_published: entry.datePublished,
        date_updated: entry.dateUpdated,
        exploited_since: entry.exploitedSince,
        cvss_score: entry.cvssScore,
        cvss_vector: entry.cvssVector,
        cvss_version: entry.cvssVersion,
        cvss_severity: entry.cvssSeverity,
        epss_score: entry.epssScore,
        reference_links: toJson(entry.references),
        aliases: toJson(entry.aliases),
        domain_categories: toJson(entry.domainCategories),
        exploit_layers: toJson(entry.exploitLayers),
        vulnerability_categories: toJson(entry.vulnerabilityCategories),
        source_url: entry.sourceUrl
      })

      if ((index + 1) % 25 === 0 || index + 1 === itemsToSave.length) {
        setImportPhase('savingEnisa', {
          message: `Saving ENISA entries (${index + 1} of ${itemsToSave.length})`,
          completed: index + 1,
          total: itemsToSave.length
        })
      }
    }
  })

  transaction(entries)

  const importedAt = new Date().toISOString()
  setMetadata('enisa.lastImportAt', importedAt)
  setMetadata('enisa.totalCount', String(entries.length))

  const latestUpdatedAt = entries
    .map(entry => entry.dateUpdated ?? entry.exploitedSince ?? entry.datePublished)
    .filter((value): value is string => typeof value === 'string')
    .sort()
    .at(-1) ?? null

  if (latestUpdatedAt) {
    setMetadata('enisa.lastUpdatedAt', latestUpdatedAt)
  }

  return {
    imported: entries.length,
    lastUpdated: latestUpdatedAt
  }
}
