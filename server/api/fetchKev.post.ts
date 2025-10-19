import { z } from 'zod'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import type { KevEntry } from '~/types'
import { fetchCvssMetrics } from '../utils/cvss'
import { importEnisaCatalog } from '../utils/enisa'
import {
  completeImportProgress,
  failImportProgress,
  setImportPhase,
  startImportProgress,
  updateImportProgress
} from '../utils/import-progress'
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

const normaliseStoredSeverity = (value: unknown): KevEntry['cvssSeverity'] | null => {
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

const SOURCE_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

type CvssMetric = {
  score: number | null
  vector: string | null
  version: string | null
  severity: KevEntry['cvssSeverity'] | null
}

export default defineEventHandler(async () => {
  startImportProgress('Starting KEV import')

  try {
    setImportPhase('preparing', { message: 'Downloading latest KEV catalog' })
    const response = await $fetch(SOURCE_URL)
    const parsed = kevSchema.safeParse(response)

    if (!parsed.success) {
      throw createError({
        statusCode: 502,
        statusMessage: 'Unable to parse KEV feed',
        data: parsed.error.flatten()
      })
    }

    const baseEntries = parsed.data.vulnerabilities.map((item): KevBaseEntry => {
      const cveId = item.cveID
      const normalised = normaliseVendorProduct({
        vendor: item.vendorProject,
        product: item.product
      })
      return {
        id: `kev:${cveId}`,
        sources: ['kev'],
        cveId,
        vendor: normalised.vendor.label,
        vendorKey: normalised.vendor.key,
        product: normalised.product.label,
        productKey: normalised.product.key,
        vulnerabilityName: item.vulnerabilityName ?? 'Unknown vulnerability',
        description: item.shortDescription ?? '',
        requiredAction: item.requiredAction ?? null,
        dateAdded: item.dateAdded ?? '',
        dueDate: item.dueDate ?? null,
        ransomwareUse: item.knownRansomwareCampaignUse ?? null,
        notes: toNotes(item.notes),
        cwes: Array.isArray(item.cwes) ? item.cwes : [],
        cvssScore: null,
        cvssVector: null,
        cvssVersion: null,
        cvssSeverity: null,
        epssScore: null,
        assigner: null,
        datePublished: item.dateAdded ?? null,
        dateUpdated: null,
        exploitedSince: item.dateAdded ?? null,
        sourceUrl: null,
        references: [],
        aliases: cveId ? [cveId] : []
      }
    })

    const db = getDatabase()
    type ExistingCvssRow = {
      cve_id: string
      cvss_score: number | null
      cvss_vector: string | null
      cvss_version: string | null
      cvss_severity: string | null
    }

    const baseCveIds = baseEntries.map(entry => entry.cveId)
    const existingCvss = new Map<string, CvssMetric>()

    if (baseCveIds.length > 0) {
      const baseCveIdSet = new Set(baseCveIds)
      const existingRows = db
        .prepare<ExistingCvssRow>(
          `SELECT cve_id, cvss_score, cvss_vector, cvss_version, cvss_severity
          FROM kev_entries
          WHERE cvss_score IS NOT NULL
            OR cvss_vector IS NOT NULL
            OR cvss_version IS NOT NULL
            OR cvss_severity IS NOT NULL`
        )
        .all() as ExistingCvssRow[]

      for (const row of existingRows) {
        if (!baseCveIdSet.has(row.cve_id)) {
          continue
        }

        existingCvss.set(row.cve_id, {
          score: typeof row.cvss_score === 'number' ? row.cvss_score : null,
          vector: typeof row.cvss_vector === 'string' ? row.cvss_vector : null,
          version: typeof row.cvss_version === 'string' ? row.cvss_version : null,
          severity: normaliseStoredSeverity(row.cvss_severity)
        })
      }
    }

    const cvesNeedingFetch = baseEntries
      .filter(entry => {
        const existing = existingCvss.get(entry.cveId)
        return !existing || existing.score === null
      })
      .map(entry => entry.cveId)

    let fetchedCvss: Map<string, CvssMetric> | null = null

    if (cvesNeedingFetch.length > 0) {
      fetchedCvss = await fetchCvssMetrics(cvesNeedingFetch, {
        onStart(total) {
          setImportPhase('fetchingCvss', {
            total,
            completed: 0,
            message:
              total > 0 ? `Fetching CVSS metrics (0 of ${total})` : 'No CVSS metrics to fetch'
          })
        },
        onProgress(completed, total) {
          const message =
            total > 0
              ? `Fetching CVSS metrics (${completed} of ${total})`
              : 'Fetching CVSS metrics'
          updateImportProgress(completed, total, message)
        }
      })
    } else {
      const reusedCount = baseEntries.length
      setImportPhase('fetchingCvss', {
        total: 0,
        completed: 0,
        message:
          reusedCount > 0
            ? `Reusing cached CVSS metrics for ${reusedCount} CVE${reusedCount === 1 ? '' : 's'}`
            : 'No CVSS metrics required for this import'
      })
    }

    const cvssMetrics = new Map<string, CvssMetric>()

    for (const base of baseEntries) {
      const existing = existingCvss.get(base.cveId)
      const fetched = fetchedCvss?.get(base.cveId)

      cvssMetrics.set(base.cveId, {
        score: fetched?.score ?? existing?.score ?? null,
        vector: fetched?.vector ?? existing?.vector ?? null,
        version: fetched?.version ?? existing?.version ?? null,
        severity: fetched?.severity ?? existing?.severity ?? null
      })
    }

    setImportPhase('enriching', { message: 'Enriching KEV entries with classification data' })

    const entries = baseEntries.map(base => {
      const metrics = cvssMetrics.get(base.cveId)
      const enrichedBase: KevBaseEntry = {
        ...base,
        cvssScore: metrics?.score ?? null,
        cvssVector: metrics?.vector ?? null,
        cvssVersion: metrics?.version ?? null,
        cvssSeverity: metrics?.severity ?? null
      }

      return enrichEntry(enrichedBase)
    })

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
      cvss_score,
      cvss_vector,
      cvss_version,
      cvss_severity,
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
      @cvss_score,
      @cvss_vector,
      @cvss_version,
      @cvss_severity,
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

        setImportPhase('saving', {
          message: 'Saving entries to the local cache',
          completed: 0,
          total: items.length
        })

        for (let index = 0; index < items.length; index += 1) {
          const entry = items[index]
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
            cvss_score: entry.cvssScore,
            cvss_vector: entry.cvssVector,
            cvss_version: entry.cvssVersion,
            cvss_severity: entry.cvssSeverity,
            domain_categories: toJson(entry.domainCategories),
            exploit_layers: toJson(entry.exploitLayers),
            vulnerability_categories: toJson(entry.vulnerabilityCategories)
          })

          if ((index + 1) % 25 === 0 || index + 1 === items.length) {
            setImportPhase('saving', {
              completed: index + 1,
              total: items.length,
              message: `Saving entries to the local cache (${index + 1} of ${items.length})`
            })
          }
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

    const enisaSummary = await importEnisaCatalog(db)

    completeImportProgress(
      `Imported ${entries.length} KEV entries and ${enisaSummary.imported} ENISA entries`
    )

    return {
      imported: entries.length + enisaSummary.imported,
      kevImported: entries.length,
      enisaImported: enisaSummary.imported,
      dateReleased: parsed.data.dateReleased,
      catalogVersion: parsed.data.catalogVersion,
      enisaLastUpdated: enisaSummary.lastUpdated,
      importedAt
    }
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Import failed'
    failImportProgress(message)
    throw error
  }
})
