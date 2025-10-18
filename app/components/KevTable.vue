<script setup lang="ts">
import { computed, h, resolveComponent } from 'vue'
import type { TableColumn } from '@nuxt/ui'
import type { KevEntry } from '~/types'

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
    cell: ({ row }) =>
      h(
        ULink,
        {
          href: `https://nvd.nist.gov/vuln/detail/${row.original.cveId}`,
          target: '_blank',
          rel: 'noopener noreferrer'
        },
        () => row.original.cveId
      )
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
    id: 'domainCategories',
    header: 'Domain',
    cell: ({ row }) => row.original.domainCategories.join(', ') || '—'
  },
  {
    id: 'exploitLayers',
    header: 'Exploit profile',
    cell: ({ row }) => row.original.exploitLayers.join(', ') || '—'
  },
  {
    id: 'vulnerabilityCategories',
    header: 'Vulnerability',
    cell: ({ row }) => row.original.vulnerabilityCategories.join(', ') || '—'
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
    cell: ({ row }) => {
      const use = row.original.ransomwareUse ?? ''
      const isKnown = use.toLowerCase().includes('known')
      return h(
        UBadge,
        {
          color: isKnown ? 'error' : 'neutral',
          variant: 'subtle'
        },
        () => (isKnown ? 'Known' : 'None')
      )
    }
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
