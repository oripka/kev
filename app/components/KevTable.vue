<script setup lang="ts">
import { computed, h, resolveComponent } from 'vue'
import type { TableColumn } from '@nuxt/ui'
import type { KevEntry } from '~/types/kev'

const props = defineProps<{
  entries: KevEntry[]
  loading: boolean
  total: number
}>()

const UBadge = resolveComponent('UBadge')
const ULink = resolveComponent('ULink')

const columns = computed<TableColumn<KevEntry>[]>(() => [
  {
    accessorKey: 'cveId',
    header: 'CVE ID',
    cell: ({ row }) => {
      const entry = row.original
      if (!entry.sources.length) return entry.cveId
      return h(
        ULink,
        {
          href: entry.sources[0],
          target: '_blank',
          rel: 'noopener'
        },
        () => entry.cveId
      )
    }
  },
  {
    accessorKey: 'vendor',
    header: 'Vendor'
  },
  {
    accessorKey: 'product',
    header: 'Product'
  },
  {
    accessorKey: 'vulnerabilityType',
    header: 'Type'
  },
  {
    accessorKey: 'category',
    header: 'Category'
  },
  {
    accessorKey: 'dateAdded',
    header: 'Added'
  },
  {
    accessorKey: 'dueDate',
    header: 'Due',
    cell: ({ row }) => row.original.dueDate ?? '—'
  },
  {
    id: 'ransomware',
    header: 'Ransomware',
    cell: ({ row }) =>
      h(
        UBadge,
        {
          color: row.original.knownRansomware ? 'error' : 'neutral',
          variant: 'subtle'
        },
        () => (row.original.knownRansomware ? 'Known' : 'None')
      )
  }
])
</script>

<template>
  <UCard>
    <template #header>
      <strong>{{ props.entries.length }} of {{ props.total }} vulnerabilities</strong>
    </template>
    <template #body>
      <div v-if="props.loading">
        <USkeleton />
      </div>
      <div v-else>
        <UTable :data="props.entries" :columns="columns" />
      </div>
    </template>
  </UCard>
</template>
