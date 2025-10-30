<script setup lang="ts">
import { computed, h, resolveComponent } from 'vue'
import type { TableColumn } from '@nuxt/ui'
import { catalogSourceBadgeMap } from '~/constants/catalogSources'
import type { KevEntrySummary } from '~/types'

const props = defineProps<{
  entries: KevEntrySummary[]
  loading: boolean
  total: number
  contextLabel?: string
}>()

const UBadge = resolveComponent('UBadge')
const ULink = resolveComponent('ULink')

const numberFormatter = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })

const formattedVisibleCount = computed(() =>
  numberFormatter.format(props.entries.length || 0)
)

const formattedTotalCount = computed(() => numberFormatter.format(props.total || 0))

const headerTitle = computed(() => {
  const base = `${formattedVisibleCount.value} of ${formattedTotalCount.value} vulnerabilities`
  if (props.contextLabel) {
    return `${base} associated with ${props.contextLabel}`
  }
  return base
})

const headlineEntries = computed(() => props.entries.slice(0, 3))

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
    id: 'vulnerabilityName',
    header: 'Vulnerability',
    cell: ({ row }) => {
      const title = row.original.vulnerabilityName || row.original.description || '—'
      const truncatedTitle = title.length > 150 ? `${title.slice(0, 147)}…` : title
      const description = row.original.description || ''
      const truncatedDescription = description.length > 150 ? `${description.slice(0, 147)}…` : description
      const vendor = row.original.vendor || ''
      const product = row.original.product || ''

      return h('div', { class: 'space-y-1' }, [
        h(
          'span',
          { class: 'font-medium text-neutral-800 dark:text-neutral-100' },
          truncatedTitle
        ),
        truncatedDescription
          ? h(
              'span',
              { class: 'block text-xs text-neutral-500 dark:text-neutral-400' },
              truncatedDescription
            )
          : null,
        vendor || product
          ? h(
              'span',
              { class: 'block text-xs text-neutral-500 dark:text-neutral-400' },
              [vendor, product].filter(Boolean).join(' · ')
            )
          : null
      ])
    }
  },
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
      <div class="space-y-2">
        <strong class="block text-sm font-semibold text-neutral-700 dark:text-neutral-200">
          {{ headerTitle }}
        </strong>
        <div
          v-if="headlineEntries.length"
          class="flex flex-wrap gap-2 text-xs text-neutral-500 dark:text-neutral-400"
        >
        <UBadge
          v-for="entry in headlineEntries"
          :key="entry.id"
          color="primary"
          variant="soft"
          class="font-medium"
        >
          <div class="flex flex-col gap-0.5 text-left">
            <span>{{ entry.cveId }}</span>
            <span class="text-[10px] text-neutral-500 dark:text-neutral-400">
              {{ entry.vulnerabilityName || entry.description || "Untitled" }}
            </span>
            <span
              v-if="entry.vendor || entry.product"
              class="text-[10px] text-neutral-400 dark:text-neutral-500"
            >
              {{ [entry.vendor, entry.product].filter(Boolean).join(" · ") }}
            </span>
          </div>
        </UBadge>
      </div>
      </div>
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
