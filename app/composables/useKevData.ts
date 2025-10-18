import { computed } from 'vue'
import { parseISO } from 'date-fns'
import type {
  KevDomainCategory,
  KevEntry,
  KevResponse,
  KevVulnerabilityCategory
} from '~/types'

export type CountDatum = {
  name: string
  count: number
}

const toDate = (value: string) => {
  const parsed = parseISO(value)
  return Number.isNaN(parsed.getTime()) ? null : parsed
}

const aggregateCounts = (
  entries: KevEntry[],
  accessor: (entry: KevEntry) => string | string[]
): CountDatum[] => {
  const counts = new Map<string, number>()

  for (const entry of entries) {
    const value = accessor(entry)
    const keys = Array.isArray(value) ? value : [value]

    for (const key of keys) {
      if (!key || key === 'Other') {
        continue
      }

      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
  }

  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
}

export const useKevData = () => {
  const { data, pending, error, refresh } = useFetch<KevResponse>('/api/kev', {
    default: () => ({
      updatedAt: '',
      entries: []
    })
  })

  const entries = computed(() => data.value?.entries ?? [])
  const updatedAt = computed(() => data.value?.updatedAt ?? '')

  const total = computed(() => entries.value.length)

  const lastAddedDate = computed(() => {
    const mostRecent = entries.value[0]
    return mostRecent ? toDate(mostRecent.dateAdded) : null
  })

  const earliestDate = computed(() => {
    const last = entries.value.at(-1)
    return last ? toDate(last.dateAdded) : null
  })

  const vendors = computed(() => aggregateCounts(entries.value, entry => entry.vendor))
  const products = computed(() => aggregateCounts(entries.value, entry => entry.product))
  const domainCategories = computed(() =>
    aggregateCounts(entries.value, entry => entry.domainCategories as KevDomainCategory[])
  )
  const vulnerabilityCategories = computed(() =>
    aggregateCounts(entries.value, entry => entry.vulnerabilityCategories as KevVulnerabilityCategory[])
  )

  const vendorTotal = computed(() => new Set(entries.value.map(entry => entry.vendor)).size)
  const productTotal = computed(() => new Set(entries.value.map(entry => entry.product)).size)

  const ransomwareCount = computed(() =>
    entries.value.filter(entry => (entry.ransomwareUse ?? '').toLowerCase() === 'known').length
  )

  return {
    data,
    entries,
    total,
    lastAddedDate,
    earliestDate,
    vendors,
    products,
    domainCategories,
    vulnerabilityCategories,
    vendorTotal,
    productTotal,
    ransomwareCount,
    updatedAt,
    pending,
    error,
    refresh
  }
}
