import type { CvssSeverity } from '~/types'

type CvssMetric = {
  score: number | null
  vector: string | null
  version: string | null
  severity: CvssSeverity | null
}

type NvdVulnerability = {
  cve: {
    id: string
    metrics?: Record<string, unknown>
  }
}

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const CHUNK_SIZE = 50
const MAX_RETRIES = 3

const sleep = (duration: number) =>
  new Promise<void>(resolve => setTimeout(resolve, duration))

const normaliseSeverity = (value?: string | null): CvssSeverity | null => {
  if (!value) {
    return null
  }

  const normalised = value.trim().toLowerCase()

  switch (normalised) {
    case 'none':
      return 'None'
    case 'low':
      return 'Low'
    case 'medium':
      return 'Medium'
    case 'high':
      return 'High'
    case 'critical':
      return 'Critical'
    default:
      return null
  }
}

const deriveSeverityFromScore = (score: number | null): CvssSeverity | null => {
  if (score === null || Number.isNaN(score)) {
    return null
  }

  if (score === 0) {
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

type RawMetric = {
  cvssData?: {
    baseScore?: number
    baseSeverity?: string
    vectorString?: string
    version?: string
  }
}

const extractMetricFromSource = (raw: unknown): RawMetric | null => {
  if (!raw || typeof raw !== 'object') {
    return null
  }

  if (Array.isArray(raw)) {
    const [primary] = raw
    return extractMetricFromSource(primary)
  }

  return raw as RawMetric
}

const extractCvssMetric = (metrics?: Record<string, unknown>): CvssMetric => {
  if (!metrics) {
    return { score: null, vector: null, version: null, severity: null }
  }

  const preferenceOrder = [
    'cvssMetricV31',
    'cvssMetricV30',
    'cvssMetricV3',
    'cvssMetricV2'
  ] as const

  for (const key of preferenceOrder) {
    const raw = metrics[key as keyof typeof metrics]
    const metric = extractMetricFromSource(raw)

    if (!metric?.cvssData) {
      continue
    }

    const data = metric.cvssData
    const score = typeof data.baseScore === 'number' ? data.baseScore : null
    const vector = typeof data.vectorString === 'string' ? data.vectorString : null
    const version = typeof data.version === 'string' ? data.version : null
    const severity = normaliseSeverity(data.baseSeverity) ?? deriveSeverityFromScore(score)

    return { score, vector, version, severity }
  }

  return { score: null, vector: null, version: null, severity: null }
}

const fetchChunk = async (ids: string[], attempt = 0): Promise<NvdVulnerability[]> => {
  if (!ids.length) {
    return []
  }

  const params = new URLSearchParams()

  for (const id of ids) {
    params.append('cveId', id)
  }

  params.append('noRejected', '')

  const url = `${NVD_API_URL}?${params.toString()}`

  try {
    const response = await $fetch<{ vulnerabilities?: NvdVulnerability[] }>(url, {
      headers: {
        'User-Agent': 'kev-watch/1.0 (+https://github.com)' // Informational header per NVD guidelines
      },
      timeout: 60_000
    })

    return response.vulnerabilities ?? []
  } catch (error) {
    if (attempt + 1 >= MAX_RETRIES) {
      console.warn('Failed to fetch CVSS metrics after retries', error)
      return []
    }

    const delay = 750 * (attempt + 1)
    await sleep(delay)
    return fetchChunk(ids, attempt + 1)
  }
}

type FetchCvssOptions = {
  onStart?: (total: number) => void
  onProgress?: (completed: number, total: number) => void
}

export const fetchCvssMetrics = async (
  cveIds: string[],
  options: FetchCvssOptions = {}
): Promise<Map<string, CvssMetric>> => {
  const unique = Array.from(new Set(cveIds.filter(Boolean)))

  const result = new Map<string, CvssMetric>()

  if (!unique.length) {
    return result
  }

  options.onStart?.(unique.length)

  for (let index = 0; index < unique.length; index += CHUNK_SIZE) {
    const chunk = unique.slice(index, index + CHUNK_SIZE)
    const vulnerabilities = await fetchChunk(chunk)

    for (const vulnerability of vulnerabilities) {
      const id = vulnerability.cve?.id
      if (!id) {
        continue
      }

      const metrics = vulnerability.cve.metrics
      result.set(id, extractCvssMetric(metrics))
    }

    const completed = Math.min(index + CHUNK_SIZE, unique.length)
    options.onProgress?.(completed, unique.length)

    // NVD limits clients to 5 requests in a 30 second window without an API key.
    if (index + CHUNK_SIZE < unique.length) {
      await sleep(6_500)
    }
  }

  // Fill any missing CVEs with null metrics to simplify downstream handling.
  for (const id of unique) {
    if (!result.has(id)) {
      result.set(id, { score: null, vector: null, version: null, severity: null })
    }
  }

  return result
}
