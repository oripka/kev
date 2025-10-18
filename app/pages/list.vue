<script setup lang="ts">
import type { KevFilterState } from '~/types'
import { useKevData } from '~/composables/useKevData'

const kev = useKevData()

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
