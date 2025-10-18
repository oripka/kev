<script setup lang="ts">
import { computed } from 'vue'
import type { TableColumn } from '@nuxt/ui'
import { useKevData } from '~/composables/useKevData'

const kev = useKevData()

const typeColumns = computed<TableColumn<{ label: string; value: number }>[]>(() => [
  {
    accessorKey: 'label',
    header: 'Vulnerability type'
  },
  {
    accessorKey: 'value',
    header: 'KEVs'
  }
])
</script>

<template>
  <section>
    <VendorChart :items="kev.topVendors.value" :total="kev.totalEntries.value" title="Top vendors" />
  </section>

  <section>
    <CategoryChart :items="kev.topCategories.value" :total="kev.totalEntries.value" title="Top categories" />
  </section>

  <section>
    <TrendChart :items="kev.timeline.value" title="Monthly KEV growth" />
  </section>

  <section>
    <UCard>
      <template #header>
        <strong>Leading vulnerability types</strong>
      </template>
      <template #body>
        <UTable :data="kev.topVulnerabilityTypes.value" :columns="typeColumns" />
      </template>
    </UCard>
  </section>
</template>
