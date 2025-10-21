import { createError, getRouterParam } from 'h3'
import { sql } from 'drizzle-orm'
import { tables } from '../../database/client'
import type { CatalogEntryRow } from '../../utils/catalog'
import { catalogRowToEntry, getMarketSignalsForProducts } from '../../utils/catalog'
import { getDatabase } from '../../utils/sqlite'
import type {
  CatalogSource,
  KevEntry,
  KevEntryTimelineEvent,
  KevTimelineEventType,
} from '~/types'

const catalogSourceValues: CatalogSource[] = ['kev', 'enisa', 'historic', 'metasploit']

const toCatalogSource = (value: string | null | undefined): CatalogSource | null => {
  if (typeof value !== 'string') {
    return null
  }

  const lower = value.toLowerCase()
  return (catalogSourceValues as string[]).includes(lower) ? (lower as CatalogSource) : null
}

const normalizeValue = (value: string | null | undefined): string | null => {
  if (!value) {
    return null
  }

  const trimmed = value.trim()
  return trimmed.length ? trimmed : null
}

const toDateOrNull = (value: string): Date | null => {
  const normalised = normalizeValue(value)
  if (!normalised) {
    return null
  }

  const parsed = new Date(normalised)
  return Number.isNaN(parsed.getTime()) ? null : parsed
}

type TimelineRow = {
  source: string | null
  date_added: string | null
  date_published: string | null
  exploited_since: string | null
  source_url: string | null
  metasploit_module_path: string | null
  updated_at: string | null
}

const buildTimelineEvents = (entry: KevEntry, rows: TimelineRow[]): KevEntryTimelineEvent[] => {
  const events: KevEntryTimelineEvent[] = []
  const seen = new Set<string>()

  const addEvent = (
    type: KevTimelineEventType,
    timestampCandidate: string | null | undefined,
    overrides: Partial<KevEntryTimelineEvent> = {},
  ) => {
    const timestamp = normalizeValue(timestampCandidate)
    if (!timestamp) {
      return
    }

    const key = `${type}:${timestamp}`
    if (seen.has(key)) {
      return
    }
    seen.add(key)

    const event: KevEntryTimelineEvent = {
      id: overrides.id ?? key,
      type,
      timestamp,
      ...(overrides.source ? { source: overrides.source } : {}),
      ...(overrides.title ? { title: overrides.title } : {}),
      ...(overrides.description ? { description: overrides.description } : {}),
      ...(overrides.metadata ? { metadata: overrides.metadata } : {}),
      ...(overrides.url !== undefined ? { url: overrides.url } : {}),
      ...(overrides.icon ? { icon: overrides.icon } : {}),
    }

    events.push(event)
  }

  const publicationMetadata =
    entry.assigner && entry.assigner.trim().length
      ? { assigner: entry.assigner }
      : undefined

  addEvent('cve_published', entry.datePublished, {
    source: 'nvd',
    ...(publicationMetadata ? { metadata: publicationMetadata } : {}),
  })

  for (const row of rows) {
    const source = toCatalogSource(row.source)
    if (!source) {
      continue
    }

    const url = normalizeValue(row.source_url) ?? undefined
    const base: Partial<KevEntryTimelineEvent> = {
      source,
      ...(url ? { url } : {}),
    }

    if (source === 'kev') {
      const timestamp =
        row.date_added ??
        row.exploited_since ??
        row.date_published ??
        entry.dateAdded ??
        null

      addEvent('kev_listed', timestamp, base)
      continue
    }

    if (source === 'enisa') {
      const timestamp = row.date_added ?? row.exploited_since ?? row.date_published ?? null
      addEvent('enisa_listed', timestamp, base)
      continue
    }

    if (source === 'metasploit') {
      const timestamp =
        row.date_published ?? row.date_added ?? row.exploited_since ?? row.updated_at ?? null

      const metadata: Record<string, string | number | boolean | null> = {}

      if (row.metasploit_module_path && row.metasploit_module_path.trim().length) {
        metadata.modulePath = row.metasploit_module_path
      }

      addEvent('metasploit_module', timestamp, {
        ...base,
        ...(Object.keys(metadata).length ? { metadata } : {}),
      })
      continue
    }

    if (source === 'historic') {
      const timestamp = row.date_added ?? row.exploited_since ?? row.date_published ?? null
      addEvent('historic_reference', timestamp, base)
    }
  }

  events.sort((first, second) => {
    const firstDate = toDateOrNull(first.timestamp)
    const secondDate = toDateOrNull(second.timestamp)

    if (firstDate && secondDate) {
      return firstDate.getTime() - secondDate.getTime()
    }

    if (firstDate) {
      return -1
    }

    if (secondDate) {
      return 1
    }

    return first.timestamp.localeCompare(second.timestamp)
  })

  return events
}

export default defineEventHandler(async event => {
  const id = getRouterParam(event, 'id')

  if (!id) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Missing entry identifier'
    })
  }

  const db = getDatabase()
  const row = db.get(
    sql<CatalogEntryRow>`
      SELECT
        ce.cve_id,
        ce.entry_id,
        ce.sources,
        ce.vendor,
        ce.vendor_key,
        ce.product,
        ce.product_key,
        ce.vulnerability_name,
        ce.description,
        ce.required_action,
        ce.date_added,
        ce.date_added_ts,
        ce.date_added_year,
        ce.due_date,
        ce.ransomware_use,
        ce.has_known_ransomware,
        ce.notes,
        ce.cwes,
        ce.cvss_score,
        ce.cvss_vector,
        ce.cvss_version,
        ce.cvss_severity,
        ce.epss_score,
        ce.assigner,
        ce.date_published,
        ce.date_updated,
        ce.date_updated_ts,
        ce.exploited_since,
        ce.source_url,
        ce.reference_links,
        ce.aliases,
        ce.metasploit_module_path,
        ce.metasploit_module_published_at,
        ce.is_well_known,
        ce.domain_categories,
        ce.exploit_layers,
        ce.vulnerability_categories,
        ce.internet_exposed,
        ce.has_source_kev,
        ce.has_source_enisa,
        ce.has_source_historic,
        ce.has_source_metasploit
      FROM ${tables.catalogEntries} ce
      WHERE ce.entry_id = ${id}
      LIMIT 1
    `
  ) as CatalogEntryRow | undefined

  if (!row) {
    throw createError({
      statusCode: 404,
      statusMessage: 'Vulnerability entry not found'
    })
  }

  const marketSignals = getMarketSignalsForProducts(
    db,
    row.product_key ? [row.product_key] : []
  )

  const entry = catalogRowToEntry(row, { marketSignals })

  const cveId = normalizeValue(entry.cveId)

  const timelineRows: TimelineRow[] = cveId
    ? (db.all(
        sql<TimelineRow>`
          SELECT
            ve.source,
            ve.date_added,
            ve.date_published,
            ve.exploited_since,
            ve.source_url,
            ve.metasploit_module_path,
            ve.updated_at
          FROM ${tables.vulnerabilityEntries} ve
          WHERE ve.cve_id IS NOT NULL AND upper(ve.cve_id) = ${cveId.toUpperCase()}
        `,
      ) as TimelineRow[])
    : []

  const timeline = buildTimelineEvents(entry, timelineRows)

  return { ...entry, timeline }
})
