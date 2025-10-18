<script setup lang="ts">
import { computed } from 'vue'
import type { KevFilterState } from '~/types'
import { useKevData } from '~/composables/useKevData'
import type { CountDatum } from '~/composables/useKevData'

const kev = useKevData()
const MAX_PROGRESS_ITEMS = 6
const percentFormatter = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 })

const toProgressItems = (items: CountDatum[]) => {
  if (!items.length) {
    return []
  }

  const total = items.reduce((sum, item) => sum + item.count, 0)
  if (!total) {
    return []
  }

  return items.slice(0, MAX_PROGRESS_ITEMS).map(item => {
    const percent = (item.count / total) * 100
    return {
      ...item,
      percent,
      percentLabel: percentFormatter.format(percent)
    }
  })
}

const domainStats = computed(() => toProgressItems(kev.filteredDomainCategories.value))
const categoryStats = computed(() => toProgressItems(kev.filteredVulnerabilityCategories.value))
const domainTotalCount = computed(() =>
  kev.filteredDomainCategories.value.reduce((sum, item) => sum + item.count, 0)
)
const categoryTotalCount = computed(() =>
  kev.filteredVulnerabilityCategories.value.reduce((sum, item) => sum + item.count, 0)
)
const hasProgressStats = computed(
  () => domainStats.value.length > 0 || categoryStats.value.length > 0
)

function updateFilters(value: KevFilterState) {
  Object.assign(kev.filters, value)
}

function resetFilters() {
  kev.resetFilters()
}

function exportCsv() {
  if (!import.meta.client) {
    return
  }

  const csv = kev.exportCsv()
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `kev-watch-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <UPage>
    <UPageHeader
      title="Catalog browser"
      description="Filter the KEV catalog and export the current view"
    />

    <UPageBody>
      <UPageSection>
        <FilterPanel
          :filters="kev.filters"
          :vendors="kev.vendorNames.value"
          :products="kev.productNames.value"
          :categories="kev.categoryNames.value"
          :vulnerability-types="kev.vulnerabilityTypeNames.value"
          @update:filters="updateFilters"
          @reset="resetFilters"
        />
      </UPageSection>

      <UPageSection v-if="hasProgressStats">
        <div class="grid gap-4 lg:grid-cols-2">
          <UCard>
            <template #header>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                    Domain coverage
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    Share of filtered results by domain
                  </p>
                </div>
                <UBadge color="primary" variant="soft">
                  {{ domainTotalCount }}
                </UBadge>
              </div>
            </template>

            <template #default>
              <div v-if="domainStats.length" class="space-y-4">
                <div
                  v-for="stat in domainStats"
                  :key="stat.name"
                  class="space-y-2"
                >
                  <div class="flex items-center justify-between text-sm">
                    <span class="font-medium text-neutral-900 dark:text-neutral-50 truncate">
                      {{ stat.name }}
                    </span>
                    <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress :model-value="stat.percent" color="primary" size="sm" />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No domain category data for this filter.
              </p>
            </template>
          </UCard>

          <UCard>
            <template #header>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                    Vulnerability mix
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    Category share across current filters
                  </p>
                </div>
                <UBadge color="violet" variant="soft">
                  {{ categoryTotalCount }}
                </UBadge>
              </div>
            </template>

            <template #default>
              <div v-if="categoryStats.length" class="space-y-4">
                <div
                  v-for="stat in categoryStats"
                  :key="stat.name"
                  class="space-y-2"
                >
                  <div class="flex items-center justify-between text-sm">
                    <span class="font-medium text-neutral-900 dark:text-neutral-50 truncate">
                      {{ stat.name }}
                    </span>
                    <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress :model-value="stat.percent" color="violet" size="sm" />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No vulnerability category data for this filter.
              </p>
            </template>
          </UCard>
        </div>
      </UPageSection>

      <UPageSection>
        <UCard>
          <template #header>
            <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
              Export results
            </p>
          </template>
          <template #default>
            <UButton color="secondary" icon="i-lucide-download" @click="exportCsv">
              Export filtered CSV
            </UButton>
          </template>
        </UCard>
      </UPageSection>

      <UPageSection>
        <KevTable
          :entries="kev.filteredEntries.value"
          :loading="kev.pending.value"
          :total="kev.totalEntries.value"
        />
      </UPageSection>
    </UPageBody>
  </UPage>
</template>
