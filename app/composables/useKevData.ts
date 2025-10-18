import { computed, reactive } from 'vue'
import { useFetch } from '#app'
import type { KevEntry, KevFeedResponse, KevFilterState } from '~/types/kev'

function createInitialFilters(): KevFilterState {
  return {
    search: '',
    vendor: null,
    product: null,
    category: null,
    vulnerabilityType: null,
    ransomwareOnly: false,
    startDate: null,
    endDate: null
  }
}

function toDate(value: string | null | undefined): Date | null {
  if (!value) return null
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? null : parsed
}

function groupBy<T>(items: T[], key: (item: T) => string): Map<string, number> {
  const map = new Map<string, number>()
  for (const item of items) {
    const resolved = key(item)
    map.set(resolved, (map.get(resolved) ?? 0) + 1)
  }
  return map
}

function sortCounts(map: Map<string, number>, limit = 10) {
  return Array.from(map.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit)
}

function sanitizeString(value: string) {
  return value.trim().toLowerCase()
}

function includesText(entry: KevEntry, query: string) {
  const resolved = sanitizeString(query)
  if (!resolved) return true

  const haystacks = [
    entry.cveId,
    entry.vendor,
    entry.product,
    entry.vulnerability,
    entry.shortDescription,
    entry.requiredAction
  ]

  return haystacks.some((text) => sanitizeString(text).includes(resolved))
}

function isWithinRange(entry: KevEntry, start: string | null, end: string | null) {
  const from = toDate(start)
  const to = toDate(end)
  if (!from && !to) return true

  const added = toDate(entry.dateAdded)
  if (!added) return false
  if (from && added < from) return false
  if (to && added > to) return false
  return true
}

function computeMonthlyTimeline(entries: KevEntry[]) {
  const counts = new Map<string, number>()
  for (const entry of entries) {
    const month = entry.dateAdded.slice(0, 7)
    if (!month) continue
    counts.set(month, (counts.get(month) ?? 0) + 1)
  }

  return Array.from(counts.entries())
    .map(([period, value]) => ({ period, value }))
    .sort((a, b) => (a.period > b.period ? 1 : -1))
}

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value)
}

function buildCsv(entries: KevEntry[]): string {
  const header = [
    'CVE ID',
    'Vendor',
    'Product',
    'Category',
    'Vulnerability Type',
    'Vulnerability',
    'Date Added',
    'Due Date',
    'Known Ransomware',
    'Description',
    'Required Action',
    'Sources'
  ]

  const rows = entries.map((entry) => [
    entry.cveId,
    entry.vendor,
    entry.product,
    entry.category,
    entry.vulnerabilityType,
    entry.vulnerability,
    entry.dateAdded,
    entry.dueDate ?? '',
    entry.knownRansomware ? 'Yes' : 'No',
    entry.shortDescription,
    entry.requiredAction,
    entry.sources.join(' | ')
  ])

  return [header, ...rows]
    .map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(','))
    .join('\n')
}

export function useKevData() {
  const filters = reactive(createInitialFilters())

  const {
    data,
    pending,
    error,
    refresh
  } = useFetch<KevFeedResponse>('/api/fetchKev', {
    key: 'kev-feed',
    transform: (response) => response
  })

  const entries = computed(() => data.value?.entries ?? [])

  const filteredEntries = computed(() =>
    entries.value.filter((entry) => {
      if (!includesText(entry, filters.search)) return false
      if (filters.vendor && entry.vendor !== filters.vendor) return false
      if (filters.product && entry.product !== filters.product) return false
      if (filters.category && entry.category !== filters.category) return false
      if (filters.vulnerabilityType && entry.vulnerabilityType !== filters.vulnerabilityType) return false
      if (filters.ransomwareOnly && !entry.knownRansomware) return false
      if (!isWithinRange(entry, filters.startDate, filters.endDate)) return false
      return true
    })
  )

  const vendors = computed(() => Array.from(new Set(entries.value.map((entry) => entry.vendor))).sort())
  const products = computed(() => Array.from(new Set(entries.value.map((entry) => entry.product))).sort())
  const categories = computed(() => Array.from(new Set(entries.value.map((entry) => entry.category))).sort())
  const vulnerabilityTypes = computed(() =>
    Array.from(new Set(entries.value.map((entry) => entry.vulnerabilityType))).sort()
  )

  const totalEntries = computed(() => entries.value.length)
  const ransomwareTotal = computed(() => entries.value.filter((entry) => entry.knownRansomware).length)

  const newThisWeek = computed(() => {
    const today = new Date()
    const sevenDaysAgo = new Date(today)
    sevenDaysAgo.setDate(today.getDate() - 7)
    return entries.value.filter((entry) => {
      const added = toDate(entry.dateAdded)
      if (!added) return false
      return added >= sevenDaysAgo
    }).length
  })

  const topVendors = computed(() => sortCounts(groupBy(entries.value, (entry) => entry.vendor)))
  const topCategories = computed(() => sortCounts(groupBy(entries.value, (entry) => entry.category)))
  const topVulnerabilityTypes = computed(() =>
    sortCounts(groupBy(entries.value, (entry) => entry.vulnerabilityType))
  )

  const timeline = computed(() => computeMonthlyTimeline(entries.value))

  const lastUpdated = computed(() => data.value?.dateReleased ?? null)
  const fetchedAt = computed(() => data.value?.fetchedAt ?? null)

  function resetFilters() {
    const next = createInitialFilters()
    Object.assign(filters, next)
  }

  function exportCsv() {
    return buildCsv(filteredEntries.value)
  }

  return {
    data,
    entries,
    filteredEntries,
    vendors,
    products,
    categories,
    vulnerabilityTypes,
    filters,
    totalEntries,
    ransomwareTotal,
    newThisWeek,
    topVendors,
    topCategories,
    topVulnerabilityTypes,
    timeline,
    lastUpdated,
    fetchedAt,
    pending,
    error,
    refresh,
    resetFilters,
    exportCsv,
    formatNumber
  }
}
