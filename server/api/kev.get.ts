import type { KevEntry, KevResponse } from '~/types'
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

const getEntries = (): KevEntry[] => {
  const db = getDatabase()
  const rows = db
    .prepare<KevRow>(
      `SELECT
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
      FROM kev_entries
      ORDER BY date(date_added) DESC, cve_id ASC`
    )
    .all()

  return rows.map(row => ({
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
}

export default defineEventHandler(async (): Promise<KevResponse> => {
  const entries = getEntries()
  const feedUpdatedAt = getMetadata('dateReleased')
  const lastImportAt = getMetadata('lastImportAt')
  const fallbackTimestamp = entries.length > 0 ? new Date().toISOString() : ''

  return {
    updatedAt: feedUpdatedAt ?? lastImportAt ?? fallbackTimestamp,
    entries
  }
})
