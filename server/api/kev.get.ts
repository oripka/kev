import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import type { KevEntry, KevResponse } from '~/types'

const KEV_SOURCE =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

export default defineEventHandler(async (): Promise<KevResponse> => {
  const payload = await $fetch<{ dateReleased?: string; vulnerabilities?: any[] }>(KEV_SOURCE)

  const entries = (payload.vulnerabilities ?? []).map((item): KevEntry => {
    const notes = typeof item.notes === 'string'
      ? item.notes.split(';').map((note: string) => note.trim()).filter(Boolean)
      : Array.isArray(item.notes)
        ? item.notes
        : []

    const cwes = Array.isArray(item.cwes) ? item.cwes : []

    const baseEntry: KevBaseEntry = {
      cveId: item.cveID,
      vendor: item.vendorProject ?? 'Unknown',
      product: item.product ?? 'Unknown',
      vulnerabilityName: item.vulnerabilityName ?? 'Unknown vulnerability',
      description: item.shortDescription ?? '',
      requiredAction: item.requiredAction ?? '',
      dateAdded: item.dateAdded ?? '',
      dueDate: item.dueDate ?? null,
      ransomwareUse: item.knownRansomwareCampaignUse ?? null,
      notes,
      cwes
    }

    return enrichEntry(baseEntry)
  })

  entries.sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())

  return {
    updatedAt: payload.dateReleased ?? new Date().toISOString(),
    entries
  }
})
