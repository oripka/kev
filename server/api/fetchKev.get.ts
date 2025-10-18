import { z } from 'zod'

const kevSchema = z.object({
  title: z.string(),
  catalogVersion: z.string(),
  dateReleased: z.string(),
  count: z.number(),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vendorProject: z.string(),
      product: z.string(),
      vulnerabilityName: z.string(),
      dateAdded: z.string(),
      shortDescription: z.string().optional(),
      requiredAction: z.string().optional(),
      dueDate: z.string().nullable().optional(),
      knownRansomwareCampaignUse: z.string().optional(),
      notes: z.string().optional(),
      cwes: z.array(z.string()).optional()
    })
  )
})

function deriveCategory(product: string): string {
  const normalized = product.toLowerCase()
  if (normalized.includes('windows')) return 'Operating Systems'
  if (normalized.includes('mac') || normalized.includes('os x')) return 'Operating Systems'
  if (normalized.includes('linux') || normalized.includes('unix')) return 'Operating Systems'
  if (normalized.includes('ios') || normalized.includes('android')) return 'Mobile'
  if (normalized.includes('router') || normalized.includes('switch') || normalized.includes('firewall')) return 'Networking'
  if (normalized.includes('wordpress') || normalized.includes('drupal') || normalized.includes('joomla')) return 'CMS'
  if (normalized.includes('chrome') || normalized.includes('edge') || normalized.includes('browser')) return 'Browsers'
  if (normalized.includes('office') || normalized.includes('excel') || normalized.includes('word')) return 'Productivity'
  if (normalized.includes('vmware') || normalized.includes('hypervisor') || normalized.includes('virtual')) return 'Virtualization'
  if (normalized.includes('exchange') || normalized.includes('email')) return 'Email & Collaboration'
  return 'Other'
}

function deriveVulnerabilityType(name: string): string {
  const lower = name.toLowerCase()
  if (lower.includes('injection')) return 'Injection'
  if (lower.includes('overflow')) return 'Memory Corruption'
  if (lower.includes('execution')) return 'Code Execution'
  if (lower.includes('spoof')) return 'Authentication'
  if (lower.includes('bypass')) return 'Security Bypass'
  if (lower.includes('xss') || lower.includes('cross-site')) return 'Cross-Site Scripting'
  if (lower.includes('csrf')) return 'Cross-Site Request Forgery'
  if (lower.includes('deserialization')) return 'Deserialization'
  if (lower.includes('directory traversal')) return 'Traversal'
  if (lower.includes('privilege escalation') || lower.includes('escalation')) return 'Privilege Escalation'
  return 'Other'
}

export default defineEventHandler(async () => {
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  const response = await $fetch(url)
  const parsed = kevSchema.safeParse(response)

  if (!parsed.success) {
    throw createError({
      statusCode: 502,
      statusMessage: 'Unable to parse KEV feed',
      data: parsed.error.flatten()
    })
  }

  const entries = parsed.data.vulnerabilities.map((item) => {
    const sources = item.notes
      ? item.notes
          .split(';')
          .map((source) => source.trim())
          .filter(Boolean)
      : []

    return {
      cveId: item.cveID,
      vendor: item.vendorProject,
      product: item.product,
      vulnerability: item.vulnerabilityName,
      vulnerabilityType: deriveVulnerabilityType(item.vulnerabilityName),
      category: deriveCategory(item.product),
      dateAdded: item.dateAdded,
      dueDate: item.dueDate ?? null,
      requiredAction: item.requiredAction ?? '',
      shortDescription: item.shortDescription ?? '',
      knownRansomware: (item.knownRansomwareCampaignUse ?? '').toLowerCase().includes('known'),
      sources,
      cwes: item.cwes ?? []
    }
  })

  return {
    title: parsed.data.title,
    catalogVersion: parsed.data.catalogVersion,
    dateReleased: parsed.data.dateReleased,
    fetchedAt: new Date().toISOString(),
    count: parsed.data.count,
    entries
  }
})
