import { computed, reactive } from 'vue'
import { parseISO } from 'date-fns'
import type {
  KevDomainCategory,
  KevEntry,
  KevExploitLayer,
  KevResponse,
  KevVulnerabilityCategory
} from '~/types'
import type { KevFilterState } from '~/types'

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

const createDefaultFilters = (): KevFilterState => ({
  search: '',
  vendor: null,
  product: null,
  category: null,
  exploitLayer: null,
  vulnerabilityType: null,
  ransomwareOnly: false,
  startDate: null,
  endDate: null
})

const toCsvValue = (value: string | string[]) => {
  const text = Array.isArray(value) ? value.join('; ') : value
  const escaped = text.replace(/"/g, '""')
  return `"${escaped}"`
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
  const filters = reactive<KevFilterState>(createDefaultFilters())

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
  const exploitLayers = computed(() =>
    aggregateCounts(entries.value, entry => entry.exploitLayers as KevExploitLayer[])
  )
  const vulnerabilityCategories = computed(() =>
    aggregateCounts(entries.value, entry => entry.vulnerabilityCategories as KevVulnerabilityCategory[])
  )

  const vendorNames = computed(() => {
    const names = new Set(entries.value.map(entry => entry.vendor).filter(Boolean))
    return Array.from(names).sort((a, b) => a.localeCompare(b))
  })

  const productNames = computed(() => {
    const names = new Set(entries.value.map(entry => entry.product).filter(Boolean))
    return Array.from(names).sort((a, b) => a.localeCompare(b))
  })

  const categoryNames = computed(() => {
    const names = new Set<string>()
    for (const entry of entries.value) {
      for (const category of entry.domainCategories) {
        names.add(category)
      }
    }
    return Array.from(names).sort((a, b) => a.localeCompare(b))
  })

  const exploitLayerNames = computed(() => {
    const names = new Set<string>()
    for (const entry of entries.value) {
      for (const layer of entry.exploitLayers) {
        names.add(layer)
      }
    }
    return Array.from(names).sort((a, b) => a.localeCompare(b))
  })

  const vulnerabilityTypeNames = computed(() => {
    const names = new Set<string>()
    for (const entry of entries.value) {
      for (const category of entry.vulnerabilityCategories) {
        names.add(category)
      }
    }
    return Array.from(names).sort((a, b) => a.localeCompare(b))
  })

  const filteredEntries = computed(() => {
    const term = filters.search.trim().toLowerCase()
    const startDate = filters.startDate ? new Date(filters.startDate) : null
    const endDate = filters.endDate ? new Date(filters.endDate) : null

    return entries.value.filter(entry => {
      if (filters.vendor && entry.vendor !== filters.vendor) {
        return false
      }

      if (filters.product && entry.product !== filters.product) {
        return false
      }

      if (
        filters.category &&
        !entry.domainCategories.includes(filters.category as KevDomainCategory)
      ) {
        return false
      }

      if (
        filters.exploitLayer &&
        !entry.exploitLayers.includes(filters.exploitLayer as KevExploitLayer)
      ) {
        return false
      }

      if (
        filters.vulnerabilityType &&
        !entry.vulnerabilityCategories.includes(filters.vulnerabilityType as KevVulnerabilityCategory)
      ) {
        return false
      }

      if (filters.ransomwareOnly) {
        const use = (entry.ransomwareUse ?? '').toLowerCase()
        if (!use.includes('known')) {
          return false
        }
      }

      if (startDate || endDate) {
        const addedOn = toDate(entry.dateAdded)
        if (!addedOn) {
          return false
        }

        if (startDate && addedOn < startDate) {
          return false
        }

        if (endDate) {
          const end = new Date(endDate)
          end.setHours(23, 59, 59, 999)
          if (addedOn > end) {
            return false
          }
        }
      }

      if (term) {
        const haystack = [
          entry.cveId,
          entry.vendor,
          entry.product,
          entry.vulnerabilityName,
          entry.description,
          ...entry.notes
        ]
          .join(' ')
          .toLowerCase()

        if (!haystack.includes(term)) {
          return false
        }
      }

      return true
    })
  })

  const totalEntries = computed(() => filteredEntries.value.length)
  const filteredDomainCategories = computed(() =>
    aggregateCounts(filteredEntries.value, entry => entry.domainCategories as KevDomainCategory[])
  )
  const filteredExploitLayers = computed(() =>
    aggregateCounts(filteredEntries.value, entry => entry.exploitLayers as KevExploitLayer[])
  )
  const filteredVulnerabilityCategories = computed(() =>
    aggregateCounts(
      filteredEntries.value,
      entry => entry.vulnerabilityCategories as KevVulnerabilityCategory[]
    )
  )

  const vendorTotal = computed(() => new Set(entries.value.map(entry => entry.vendor)).size)
  const productTotal = computed(() => new Set(entries.value.map(entry => entry.product)).size)

  const ransomwareCount = computed(() =>
    entries.value.filter(entry => (entry.ransomwareUse ?? '').toLowerCase() === 'known').length
  )

  const resetFilters = () => {
    Object.assign(filters, createDefaultFilters())
  }

  const exportCsv = () => {
    const header = [
      'CVE ID',
      'Vendor',
      'Product',
      'Vulnerability',
      'Date Added',
      'Ransomware Use',
      'Domain Categories',
      'Exploit Layers',
      'Vulnerability Categories',
      'Description',
      'Required Action',
      'Notes',
      'CWEs'
    ].map(toCsvValue).join(',')

    const rows = filteredEntries.value.map(entry => {
      return [
        toCsvValue(entry.cveId),
        toCsvValue(entry.vendor),
        toCsvValue(entry.product),
        toCsvValue(entry.vulnerabilityName),
        toCsvValue(entry.dateAdded),
        toCsvValue(entry.ransomwareUse ?? ''),
        toCsvValue(entry.domainCategories),
        toCsvValue(entry.exploitLayers),
        toCsvValue(entry.vulnerabilityCategories),
        toCsvValue(entry.description),
        toCsvValue(entry.requiredAction),
        toCsvValue(entry.notes),
        toCsvValue(entry.cwes)
      ].join(',')
    })

    return [header, ...rows].join('\n')
  }

  return {
    data,
    entries,
    filters,
    filteredEntries,
    totalEntries,
    total,
    lastAddedDate,
    earliestDate,
    vendors,
    products,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    filteredDomainCategories,
    filteredExploitLayers,
    filteredVulnerabilityCategories,
    vendorNames,
    productNames,
    categoryNames,
    exploitLayerNames,
    vulnerabilityTypeNames,
    vendorTotal,
    productTotal,
    ransomwareCount,
    resetFilters,
    exportCsv,
    updatedAt,
    pending,
    error,
    refresh
  }
}
