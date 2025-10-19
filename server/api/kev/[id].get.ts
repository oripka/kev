import { createError, getRouterParam } from 'h3'
import type { CatalogEntryRow } from '../../utils/catalog'
import { catalogRowToEntry } from '../../utils/catalog'
import { getDatabase } from '../../utils/sqlite'

export default defineEventHandler(async event => {
  const id = getRouterParam(event, 'id')

  if (!id) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Missing entry identifier'
    })
  }

  const db = getDatabase()
  const row = db
    .prepare<CatalogEntryRow>(
      `SELECT
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
        ce.is_well_known,
        ce.domain_categories,
        ce.exploit_layers,
        ce.vulnerability_categories,
        ce.internet_exposed,
        ce.has_source_kev,
        ce.has_source_enisa
      FROM catalog_entries ce
      WHERE ce.entry_id = @id
      LIMIT 1`
    )
    .get({ id }) as CatalogEntryRow | undefined

  if (!row) {
    throw createError({
      statusCode: 404,
      statusMessage: 'Vulnerability entry not found'
    })
  }

  return catalogRowToEntry(row)
})
