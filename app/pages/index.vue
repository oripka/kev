<script setup lang="ts">
import { computed } from 'vue'
import { useKevData } from '~/composables/useKevData'

const kev = useKevData()

const summaryCards = computed(() => [
  {
    title: 'Total KEV entries',
    value: kev.formatNumber(kev.totalEntries.value),
    description: 'All vulnerabilities tracked in the catalog.',
    icon: 'i-lucide-list'
  },
  {
    title: 'New this week',
    value: kev.formatNumber(kev.newThisWeek.value),
    description: 'Entries added in the last 7 days.',
    icon: 'i-lucide-calendar-plus'
  },
  {
    title: 'Ransomware-related',
    value: kev.formatNumber(kev.ransomwareTotal.value),
    description: 'Known ransomware campaigns referencing the CVE.',
    icon: 'i-lucide-shield-alert'
  }
])

const lastUpdatedText = computed(() => kev.lastUpdated.value ?? 'Unknown')
const fetchedAtText = computed(() => kev.fetchedAt.value ?? 'Not fetched yet')
const errorMessage = computed(() => {
  const current = kev.error.value
  if (!current) return ''
  return current instanceof Error ? current.message : String(current)
})

function refreshData() {
  kev.refresh()
}
</script>

<template>
  <section>
    <UCard>
      <template #header>
        <strong>Catalog status</strong>
      </template>
      <template #body>
        <UText>Last release: {{ lastUpdatedText }}</UText>
        <UText color="neutral" variant="subtle">Last fetched: {{ fetchedAtText }}</UText>
        <UAlert
          v-if="kev.error.value"
          color="error"
          variant="subtle"
          title="Failed to update"
          :description="errorMessage"
          icon="i-lucide-alert-triangle"
        />
      </template>
      <template #footer>
        <UButton :loading="kev.pending.value" color="primary" icon="i-lucide-refresh-ccw" @click="refreshData">
          Refresh from CISA
        </UButton>
      </template>
    </UCard>
  </section>

  <section v-for="card in summaryCards" :key="card.title">
    <StatCard :title="card.title" :value="card.value" :description="card.description" :icon="card.icon" />
  </section>

  <section>
    <VendorChart :items="kev.topVendors.value" :total="kev.totalEntries.value" title="Top vendors by KEV count" />
  </section>

  <section>
    <CategoryChart
      :items="kev.topCategories.value"
      :total="kev.totalEntries.value"
      title="Top product categories"
    />
  </section>
</template>
