import { createError, getRouterParam } from 'h3'
import { sql, tables, useDrizzle } from '../../utils/drizzle'
import type { CatalogEntryRow } from '../../utils/catalog'
import { catalogRowToEntry, getMarketSignalsForProducts } from '../../utils/catalog'
import type {
  CatalogSource,
  KevAffectedProduct,
  KevEntry,
  KevEntryTimelineEvent,
  KevProblemType,
  KevTimelineEventType,
} from '~/types'

const catalogSourceValues: CatalogSource[] = ['kev', 'enisa', 'historic', 'metasploit', 'poc']

const toCatalogSource = (value: string | null | undefined): CatalogSource | null => {
  if (typeof value !== 'string') {
    return null
  }

  const lower = value.toLowerCase()
  return (catalogSourceValues as string[]).includes(lower) ? (lower as CatalogSource) : null
}

const parseAffectedProductsJson = (value: string | null): KevAffectedProduct[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }

    return parsed
      .map((item): KevAffectedProduct | null => {
        if (!item || typeof item !== 'object') {
          return null
        }

        const vendor = typeof (item as Record<string, unknown>).vendor === 'string' ? (item as Record<string, unknown>).vendor : ''
        const vendorKey =
          typeof (item as Record<string, unknown>).vendorKey === 'string'
            ? (item as Record<string, unknown>).vendorKey
            : ''
        const product = typeof (item as Record<string, unknown>).product === 'string' ? (item as Record<string, unknown>).product : ''
        const productKey =
          typeof (item as Record<string, unknown>).productKey === 'string'
            ? (item as Record<string, unknown>).productKey
            : ''

        const statusRaw = (item as Record<string, unknown>).status
        const status = typeof statusRaw === 'string' ? statusRaw : statusRaw === null ? null : undefined

        const sourceRaw = (item as Record<string, unknown>).source
        const sourceValue =
          typeof sourceRaw === 'string' ? sourceRaw.toLowerCase() : 'cna'
        const source: KevAffectedProduct['source'] =
          sourceValue === 'adp' || sourceValue === 'cpe'
            ? (sourceValue as KevAffectedProduct['source'])
            : 'cna'

        const platformsRaw = (item as Record<string, unknown>).platforms
        const platforms = Array.isArray(platformsRaw)
          ? platformsRaw.filter((platform): platform is string => typeof platform === 'string')
          : []

        const versionsRaw = (item as Record<string, unknown>).versions
        const versions = Array.isArray(versionsRaw)
          ? versionsRaw
              .filter(version => version && typeof version === 'object')
              .map(version => {
                const record = version as Record<string, unknown>
                return {
                  version: typeof record.version === 'string' ? record.version : null,
                  introduced: typeof record.introduced === 'string' ? record.introduced : null,
                  fixed: typeof record.fixed === 'string' ? record.fixed : null,
                  lessThan: typeof record.lessThan === 'string' ? record.lessThan : null,
                  lessThanOrEqual:
                    typeof record.lessThanOrEqual === 'string' ? record.lessThanOrEqual : null,
                  greaterThan: typeof record.greaterThan === 'string' ? record.greaterThan : null,
                  greaterThanOrEqual:
                    typeof record.greaterThanOrEqual === 'string'
                      ? record.greaterThanOrEqual
                      : null,
                  status: typeof record.status === 'string' ? record.status : null,
                  versionType: typeof record.versionType === 'string' ? record.versionType : null
                }
              })
          : []

        return {
          vendor,
          vendorKey,
          product,
          productKey,
          status,
          source,
          platforms,
          versions
        }
      })
      .filter((item): item is KevAffectedProduct => item !== null)
  } catch {
    return []
  }
}

const parseProblemTypesJson = (value: string | null): KevProblemType[] => {
  if (!value) {
    return []
  }

  try {
    const parsed = JSON.parse(value) as unknown
    if (!Array.isArray(parsed)) {
      return []
    }

    return parsed
      .map((item): KevProblemType | null => {
        if (!item || typeof item !== 'object') {
          return null
        }

        const record = item as Record<string, unknown>
        const description = typeof record.description === 'string' ? record.description : ''
        if (!description) {
          return null
        }

        const cweId = typeof record.cweId === 'string' && record.cweId.trim().length ? record.cweId : undefined
        const sourceValue =
          typeof record.source === 'string' && record.source.toLowerCase() === 'adp'
            ? 'adp'
            : 'cna'

        return { description, cweId, source: sourceValue }
      })
      .filter((item): item is KevProblemType => item !== null)
  } catch {
    return []
  }
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

    if (source === 'poc') {
      const timestamp =
        row.poc_published_at ?? row.date_added ?? row.exploited_since ?? row.date_published ?? null
      const pocUrl = row.poc_url ?? null

      addEvent('poc_published', timestamp, {
        ...base,
        ...(pocUrl ? { url: pocUrl } : {}),
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

  const db = useDrizzle()
  const row = await db.get(
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
        ce.poc_url,
        ce.poc_published_at,
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

  const marketSignals = await getMarketSignalsForProducts(
    db,
    row.product_key ? [row.product_key] : []
  )

  const entry = catalogRowToEntry(row, { marketSignals })

  const cveId = normalizeValue(entry.cveId)

  const detailRow = await db.get(
    sql<{ affected_products: string | null; problem_types: string | null }>`
      SELECT
        ve.affected_products,
        ve.problem_types
      FROM ${tables.vulnerabilityEntries} ve
      WHERE ve.id = ${row.entry_id}
      LIMIT 1
    `
  )

  entry.affectedProducts = parseAffectedProductsJson(detailRow?.affected_products ?? null)
  entry.problemTypes = parseProblemTypesJson(detailRow?.problem_types ?? null)

  const timelineRows: TimelineRow[] = cveId
    ? ((await db.all(
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
        `
      )) as TimelineRow[])
    : []

  const timeline = buildTimelineEvents(entry, timelineRows)

  return { ...entry, timeline }
})
