<script setup lang="ts">
import { computed, h, resolveComponent } from 'vue'
import type { TableColumn } from '@nuxt/ui'
import { catalogSourceBadgeMap } from '~/constants/catalogSources'
import type { KevEntrySummary } from '~/types'

const props = defineProps<{
  entries: KevEntrySummary[]
  loading: boolean
  total: number
}>()

const UBadge = resolveComponent('UBadge')
const ULink = resolveComponent('ULink')

const severityColors: Record<Exclude<KevEntrySummary['cvssSeverity'], null>, string> = {
  None: 'success',
  Low: 'primary',
  Medium: 'warning',
  High: 'error',
  Critical: 'error'
}

const formatScore = (score: number | null) =>
  typeof score === 'number' && Number.isFinite(score) ? score.toFixed(1) : null

const formatEpss = (score: number | null) =>
  typeof score === 'number' && Number.isFinite(score) ? score.toFixed(1) : null

const buildCvssLabel = (
  severity: KevEntrySummary['cvssSeverity'],
  score: number | null
) => {
  const parts: string[] = []

  if (severity) {
    parts.push(severity)
  }

  const formattedScore = formatScore(score)
  if (formattedScore) {
    parts.push(formattedScore)
  }

  if (!parts.length) {
    parts.push('Unknown')
  }

  return parts.join(' ')
}

const columns = computed<TableColumn<KevEntrySummary>[]>(() => [
  {
    accessorKey: 'cveId',
    header: 'CVE ID',
    cell: ({ row }) =>
      h('div', { class: 'flex flex-col gap-1' }, [
        h(
          ULink,
          {
            href: `https://nvd.nist.gov/vuln/detail/${row.original.cveId}`,
            target: '_blank',
            rel: 'noopener noreferrer'
          },
          () => row.original.cveId
        ),
        row.original.sources.length
          ? h(
              'div',
              { class: 'flex flex-wrap gap-2' },
              row.original.sources.map(source =>
                h(
                  UBadge,
                  {
                    color: catalogSourceBadgeMap[source]?.color ?? 'neutral',
                    variant: 'soft',
                    class: 'text-xs font-semibold'
                  },
                  () => catalogSourceBadgeMap[source]?.label ?? source.toUpperCase()
                )
              )
            )
          : null
      ])
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
    id: 'cvss',
    header: 'CVSS',
    cell: ({ row }) => {
      const { cvssScore, cvssSeverity } = row.original
      const formattedScore = formatScore(cvssScore)

      if (!formattedScore && !cvssSeverity) {
        return '—'
      }

      const label = buildCvssLabel(cvssSeverity, cvssScore)

      const color = cvssSeverity ? severityColors[cvssSeverity] ?? 'neutral' : 'neutral'

      return h(
        UBadge,
        {
          color,
          variant: 'soft',
          class: 'font-semibold'
        },
        () => label
      )
    }
  },
  {
    id: 'epss',
    header: 'EPSS',
    cell: ({ row }) => {
      const formatted = formatEpss(row.original.epssScore)

      if (!formatted) {
        return '—'
      }

      return h(
        UBadge,
        {
          color: 'success',
          variant: 'soft',
          class: 'font-semibold'
        },
        () => `${formatted}%`
      )
    }
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
