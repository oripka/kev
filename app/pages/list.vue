<script setup lang="ts">
import { useKevData } from '~/composables/useKevData'

const kev = useKevData()

function updateFilters(value: typeof kev.filters) {
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
  <section>
    <FilterPanel
      :filters="kev.filters"
      :vendors="kev.vendors.value"
      :products="kev.products.value"
      :categories="kev.categories.value"
      :vulnerability-types="kev.vulnerabilityTypes.value"
      @update:filters="updateFilters"
      @reset="resetFilters"
    />
  </section>

  <section>
    <UCard>
      <template #header>
        <strong>Results</strong>
      </template>
      <template #body>
        <UButton color="secondary" icon="i-lucide-download" @click="exportCsv">Export filtered CSV</UButton>
      </template>
    </UCard>
  </section>

  <section>
    <KevTable :entries="kev.filteredEntries.value" :loading="kev.pending.value" :total="kev.totalEntries.value" />
  </section>
</template>
