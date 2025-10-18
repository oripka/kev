<script setup lang="ts">
import { computed } from 'vue'
import type { TableColumn } from '@nuxt/ui'

const props = defineProps<{
  items: { period: string; value: number }[]
  title?: string
}>()

const columns = computed<TableColumn<{ period: string; value: number }>[]>(() => [
  {
    accessorKey: 'period',
    header: 'Month'
  },
  {
    accessorKey: 'value',
    header: 'KEVs added'
  }
])
</script>

<template>
  <UCard>
    <template #header>
      <strong>{{ props.title ?? 'Monthly trend' }}</strong>
    </template>
    <template #body>
      <UTable :data="props.items" :columns="columns" />
    </template>
  </UCard>
</template>
