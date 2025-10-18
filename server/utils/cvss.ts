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
const MAX_RETRIES = 5
const RATE_LIMIT_WAIT = 1_000
const RATE_LIMIT_BUFFER = 250
const DEFAULT_RATE_LIMIT = { requests: 500, window: 30_000 }
const API_KEY_RATE_LIMIT = { requests: 50, window: 30_000 }
const API_KEY = process.env.NVD_API_KEY

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

const getErrorStatus = (error: unknown): number | undefined => {
  if (!error || typeof error !== 'object') {
    return undefined
  }

  if ('status' in error && typeof (error as { status?: unknown }).status === 'number') {
    return (error as { status: number }).status
  }

  if ('statusCode' in error && typeof (error as { statusCode?: unknown }).statusCode === 'number') {
    return (error as { statusCode: number }).statusCode
  }

  const response = (error as { response?: { status?: number } }).response
  if (response && typeof response.status === 'number') {
    return response.status
  }

  return undefined
}

type RateLimitConfig = {
  requests: number
  window: number
}

const applyRateLimit = async (log: number[], limit: RateLimitConfig) => {
  while (true) {
    const now = Date.now()

    while (log.length && now - log[0] > limit.window) {
      log.shift()
    }

    if (log.length < limit.requests) {
      log.push(Date.now())
      return
    }

    const wait = limit.window - (now - log[0]) + RATE_LIMIT_BUFFER
    await sleep(Math.max(wait, RATE_LIMIT_BUFFER))
  }
}

const fetchMetricForId = async (
  id: string,
  log: number[],
  limit: RateLimitConfig,
  attempt = 0
): Promise<CvssMetric | null> => {
  if (!id) {
    return null
  }

  await applyRateLimit(log, limit)

  const params = new URLSearchParams()
  params.append('cveId', id)
  params.append('noRejected', '')

  const url = `${NVD_API_URL}?${params.toString()}`

  try {
    const response = await $fetch<{ vulnerabilities?: NvdVulnerability[] }>(url, {
      headers: {
        'User-Agent': 'kev-watch/1.0 (+https://github.com)', // Informational header per NVD guidelines
        ...(API_KEY ? { apiKey: API_KEY } : {})
      },
      timeout: 60_000
    })

    const vulnerabilities = response.vulnerabilities ?? []

    if (!vulnerabilities.length) {
      return null
    }

    const vulnerability =
      vulnerabilities.find(entry => entry.cve?.id === id) ?? vulnerabilities[0]
    return vulnerability?.cve ? extractCvssMetric(vulnerability.cve.metrics) : null
  } catch (error) {
    const status = getErrorStatus(error)
    const isRateLimited = status === 429 || status === 403

    if (attempt + 1 >= MAX_RETRIES) {
      console.warn('Failed to fetch CVSS metrics after retries', { status, error })
      return null
    }

    const delay = isRateLimited ? RATE_LIMIT_WAIT * (attempt + 1) : 750 * (attempt + 1)
    console.warn(
      `CVSS fetch attempt ${attempt + 1} failed${status ? ` (status ${status})` : ''}, retrying in ${
        delay / 1000
      }s`
    )
    await sleep(delay)
    return fetchMetricForId(id, log, limit, attempt + 1)
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

  const requestLog: number[] = []
  const rateLimit = API_KEY ? API_KEY_RATE_LIMIT : DEFAULT_RATE_LIMIT

  let completed = 0

  for (const id of unique) {
    const metrics = await fetchMetricForId(id, requestLog, rateLimit)
    if (metrics) {
      result.set(id, metrics)
    }

    completed += 1
    options.onProgress?.(completed, unique.length)
  }

  // Fill any missing CVEs with null metrics to simplify downstream handling.
  for (const id of unique) {
    if (!result.has(id)) {
      result.set(id, { score: null, vector: null, version: null, severity: null })
    }
  }

  return result
}
