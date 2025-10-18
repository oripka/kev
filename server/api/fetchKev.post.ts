import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import type { KevEntry } from '~/types'
import { getDatabase } from '../utils/sqlite'

const kevSchema = z.object({
  title: z.string(),
  catalogVersion: z.string(),
  dateReleased: z.string(),
  count: z.number(),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vendorProject: z.string().optional(),
      product: z.string().optional(),
      vulnerabilityName: z.string().optional(),
      dateAdded: z.string().optional(),
      shortDescription: z.string().optional(),
      requiredAction: z.string().optional(),
      dueDate: z.string().nullable().optional(),
      knownRansomwareCampaignUse: z.string().optional(),
      notes: z.string().optional(),
      cwes: z.array(z.string()).optional()
    })
  )
})

const toNotes = (raw: unknown): string[] => {
  if (typeof raw !== 'string') {
    return []
  }

  return raw
    .split(';')
    .map(entry => entry.trim())
    .filter(Boolean)
}

const toJson = (value: string[] | undefined | null): string => JSON.stringify(value ?? [])

const SOURCE_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

export default defineEventHandler(async () => {
  const response = await $fetch(SOURCE_URL)
  const parsed = kevSchema.safeParse(response)

  if (!parsed.success) {
    throw createError({
      statusCode: 502,
      statusMessage: 'Unable to parse KEV feed',
      data: parsed.error.flatten()
    })
  }

  const entries = parsed.data.vulnerabilities.map((item): KevEntry => {
    const base: KevBaseEntry = {
      cveId: item.cveID,
      vendor: item.vendorProject ?? 'Unknown',
      product: item.product ?? 'Unknown',
      vulnerabilityName: item.vulnerabilityName ?? 'Unknown vulnerability',
      description: item.shortDescription ?? '',
      requiredAction: item.requiredAction ?? '',
      dateAdded: item.dateAdded ?? '',
      dueDate: item.dueDate ?? null,
      ransomwareUse: item.knownRansomwareCampaignUse ?? null,
      notes: toNotes(item.notes),
      cwes: Array.isArray(item.cwes) ? item.cwes : []
    }

    return enrichEntry(base)
  })

  const db = getDatabase()
  const deleteEntries = db.prepare('DELETE FROM kev_entries')
  const insertEntry = db.prepare(
    `INSERT INTO kev_entries (
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
      vulnerability_categories,
      updated_at
    ) VALUES (
      @cve_id,
      @vendor,
      @product,
      @vulnerability_name,
      @description,
      @required_action,
      @date_added,
      @due_date,
      @ransomware_use,
      @notes,
      @cwes,
      @domain_categories,
      @exploit_layers,
      @vulnerability_categories,
      CURRENT_TIMESTAMP
    )`
  )
  const upsertMetadata = db.prepare(
    `INSERT INTO kev_metadata (key, value) VALUES (@key, @value)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  )

  const transaction = db.transaction(
    (
      items: KevEntry[],
      meta: { dateReleased: string; catalogVersion: string; count: number; importedAt: string }
    ) => {
      deleteEntries.run()

      for (const entry of items) {
        insertEntry.run({
          cve_id: entry.cveId,
          vendor: entry.vendor,
          product: entry.product,
          vulnerability_name: entry.vulnerabilityName,
          description: entry.description,
          required_action: entry.requiredAction,
          date_added: entry.dateAdded,
          due_date: entry.dueDate,
          ransomware_use: entry.ransomwareUse,
          notes: toJson(entry.notes),
          cwes: toJson(entry.cwes),
          domain_categories: toJson(entry.domainCategories),
          exploit_layers: toJson(entry.exploitLayers),
          vulnerability_categories: toJson(entry.vulnerabilityCategories)
        })
      }

      upsertMetadata.run({ key: 'dateReleased', value: meta.dateReleased })
      upsertMetadata.run({ key: 'catalogVersion', value: meta.catalogVersion })
      upsertMetadata.run({ key: 'entryCount', value: String(meta.count) })
      upsertMetadata.run({ key: 'lastImportAt', value: meta.importedAt })
    }
  )

  const importedAt = new Date().toISOString()
  transaction(entries, {
    dateReleased: parsed.data.dateReleased,
    catalogVersion: parsed.data.catalogVersion,
    count: entries.length,
    importedAt
  })

  return {
    imported: entries.length,
    dateReleased: parsed.data.dateReleased,
    catalogVersion: parsed.data.catalogVersion,
    importedAt
  }
})
