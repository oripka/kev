<script setup lang="ts">
import { computed } from 'vue'
import type { TableColumn } from '@nuxt/ui'

const props = defineProps<{
  items: { label: string; value: number }[]
  total: number
  title?: string
}>()

const columns = computed<TableColumn<{ label: string; value: number }>[]>(() => [
  {
    accessorKey: 'label',
    header: 'Category'
  },
  {
    accessorKey: 'value',
    header: 'KEVs'
  },
  {
    id: 'share',
    header: 'Share',
    cell: ({ row }) => {
      if (!props.total) return '0%'
      const ratio = (row.original.value / props.total) * 100
      return `${ratio.toFixed(1)}%`
    }
  }
])
</script>

<template>
  <UCard>
    <template #header>
      <strong>{{ props.title ?? 'Top Categories' }}</strong>
    </template>
    <template #body>
      <UTable :data="props.items" :columns="columns" />
    </template>
  </UCard>
</template>
