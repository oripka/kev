<script setup lang="ts">
import { computed } from 'vue'
import type { TrackedProduct } from '~/types'
import type {
  TrackedProductInsight,
  TrackedProductSummary,
  TrackedProductTrendPoint
} from '~/composables/useTrackedProducts'

const props = defineProps<{
  trackedProducts: TrackedProduct[]
  trackedProductCount: number
  hasTrackedProducts: boolean
  saving: boolean
  saveError: string | null
  manageHref?: string
  productInsights?: TrackedProductInsight[]
  summary?: TrackedProductSummary | null
  showReportCta?: boolean
}>()

const showOwnedOnly = defineModel<boolean>({ default: false })

const emits = defineEmits<{
  remove: [string]
  clear: []
  manage: []
  'show-report': []
}>()

const manageHref = computed(() => props.manageHref ?? '/settings/software')
const showReportCta = computed(() => props.showReportCta !== false)
const sortedInsights = computed(() => {
  const list = props.productInsights ?? []

  return [...list].sort((a, b) => {
    if (b.recentCount !== a.recentCount) {
      return b.recentCount - a.recentCount
    }

    if (b.totalCount !== a.totalCount) {
      return b.totalCount - a.totalCount
    }

    return a.product.productName.localeCompare(b.product.productName)
  })
})
const summary = computed<TrackedProductSummary>(() =>
  props.summary ?? {
    productCount: props.trackedProductCount,
    totalCount: 0,
    recentCount: 0,
    severityBreakdown: [],
    recentWindowLabel: '30 days',
    hasData: false
  }
)

const severityBarClassMap: Record<string, string> = {
  error: 'bg-rose-500/80',
  warning: 'bg-amber-500/80',
  primary: 'bg-sky-500/80',
  success: 'bg-emerald-500/80',
  neutral: 'bg-neutral-500/70'
}

const severitySoftBarClassMap: Record<string, string> = {
  error: 'bg-rose-500/70',
  warning: 'bg-amber-500/70',
  primary: 'bg-sky-500/70',
  success: 'bg-emerald-500/70',
  neutral: 'bg-neutral-500/60'
}

const severityDotClassMap: Record<string, string> = {
  error: 'bg-rose-500',
  warning: 'bg-amber-500',
  primary: 'bg-sky-500',
  success: 'bg-emerald-500',
  neutral: 'bg-neutral-500'
}

const headerStatus = computed(() => {
  if (props.saving) {
    return 'Saving…'
  }
  if (props.saveError) {
    return props.saveError
  }

  if (!props.hasTrackedProducts) {
    return 'No products selected yet'
  }

  if (summary.value.hasData) {
    return `${props.trackedProductCount} product${
      props.trackedProductCount === 1 ? '' : 's'
    } · ${summary.value.totalCount.toLocaleString()} CVEs tracked`
  }

  return `${props.trackedProductCount} product${
    props.trackedProductCount === 1 ? '' : 's'
  } selected`
})

const hasInsights = computed(() => sortedInsights.value.length > 0)

const getTrendMax = (trend: TrackedProductTrendPoint[]) =>
  trend.reduce((max, item) => (item.count > max ? item.count : max), 0)

const computeSparkHeight = (value: number, max: number) => {
  if (!max) {
    return '12%'
  }

  const percent = Math.max(12, Math.round((value / max) * 100))
  return `${percent}%`
}

const handleReportClick = () => {
  emits('show-report')
}
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="space-y-1">
          <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
            My software focus
          </p>
        </div>
        <div class="flex flex-col leading-tight">
          <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
            {{ headerStatus }}
          </span>
        </div>
      </div>
    </template>

    <div class="space-y-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <USwitch
            v-model="showOwnedOnly"
            :disabled="!props.hasTrackedProducts"
            aria-label="Limit catalog to tracked software"
          />
          <div class="flex flex-col leading-tight">
            <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
              Focus on my software
            </span>
            <span class="text-xs text-neutral-500 dark:text-neutral-400">
              {{
                showOwnedOnly
                  ? 'Catalog filtered to tracked products'
                  : 'Toggle to restrict analytics to your list'
              }}
            </span>
          </div>
        </div>

        <div v-if="props.hasTrackedProducts" class="flex items-center gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            size="xs"
            :to="manageHref"
            @click="emits('manage')"
          >
            Manage list
          </UButton>
          <UButton
            v-if="showReportCta"
            color="primary"
            size="xs"
            icon="i-lucide-activity"
            @click="handleReportClick"
          >
            View detailed report
          </UButton>
        </div>
      </div>

      <div v-if="props.trackedProducts.length" class="space-y-4">
        <div
          v-if="summary.hasData"
          class="space-y-3 rounded-xl border border-primary-200/80 bg-primary-50/60 p-4 dark:border-primary-500/50 dark:bg-primary-500/10"
        >
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex flex-wrap items-center gap-2 text-xs">
              <UBadge color="primary" variant="soft" class="font-semibold">
                {{ summary.recentCount.toLocaleString() }} new ·
                {{ summary.recentWindowLabel }}
              </UBadge>
              <UBadge color="neutral" variant="soft" class="font-semibold">
                {{ summary.totalCount.toLocaleString() }} total CVEs tracked
              </UBadge>
            </div>
            <UButton
              v-if="showReportCta"
              color="primary"
              variant="soft"
              size="xs"
              @click="handleReportClick"
            >
              Open report
            </UButton>
          </div>

          <div
            v-if="summary.severityBreakdown.length"
            class="space-y-2 text-xs text-neutral-600 dark:text-neutral-300"
          >
            <div class="h-2 overflow-hidden rounded-full bg-primary-200/60 dark:bg-primary-500/30">
              <div
                v-for="slice in summary.severityBreakdown"
                :key="slice.key"
                class="h-full"
                :class="severityBarClassMap[slice.color] ?? severityBarClassMap.neutral"
                :style="{ width: `${slice.percent}%` }"
              />
            </div>
            <div class="flex flex-wrap gap-2 text-[11px]">
              <span
                v-for="slice in summary.severityBreakdown"
                :key="slice.key"
                class="inline-flex items-center gap-1 rounded-full border border-neutral-200 bg-white/80 px-2 py-0.5 dark:border-neutral-700 dark:bg-neutral-900/60"
              >
                <span
                  class="h-2 w-2 rounded-full"
                  :class="severityDotClassMap[slice.color] ?? severityDotClassMap.neutral"
                />
                {{ slice.label }} · {{ slice.count.toLocaleString() }}
              </span>
            </div>
          </div>
        </div>

        <div v-if="hasInsights" class="grid gap-3 md:grid-cols-2">
          <div
            v-for="insight in sortedInsights"
            :key="insight.product.productKey"
            class="space-y-3 rounded-xl border border-neutral-200 bg-white/70 p-4 dark:border-neutral-800 dark:bg-neutral-900/50"
          >
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0 space-y-1">
                <p class="truncate text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                  {{ insight.product.productName }}
                </p>
                <p class="truncate text-xs text-neutral-500 dark:text-neutral-400">
                  {{ insight.product.vendorName }}
                </p>
              </div>
              <div class="flex flex-col items-end gap-1 text-xs">
                <UBadge color="neutral" variant="soft" class="font-semibold">
                  {{ insight.totalCount.toLocaleString() }} CVEs
                </UBadge>
                <UButton
                  color="neutral"
                  variant="ghost"
                  size="xs"
                  @click="emits('remove', insight.product.productKey)"
                >
                  Remove
                </UButton>
              </div>
            </div>

            <div class="flex flex-wrap items-center gap-2 text-xs">
              <UBadge color="primary" variant="soft" class="font-semibold">
                {{ insight.recentCount.toLocaleString() }} new ·
                {{ summary.recentWindowLabel }}
              </UBadge>
              <span
                v-if="insight.latestAddedAt"
                class="rounded-full border border-neutral-200 bg-white/80 px-2 py-0.5 text-[11px] text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900/40 dark:text-neutral-400"
              >
                Latest: {{ insight.latestAddedAt }}
              </span>
            </div>

            <div v-if="insight.severityBreakdown.length" class="space-y-2">
              <div class="h-2 overflow-hidden rounded-full bg-neutral-200/70 dark:bg-neutral-800/70">
                <div
                  v-for="slice in insight.severityBreakdown"
                  :key="slice.key"
                  class="h-full"
                  :class="severitySoftBarClassMap[slice.color] ?? severitySoftBarClassMap.neutral"
                  :style="{ width: `${slice.percent}%` }"
                />
              </div>
              <div class="flex flex-wrap gap-1 text-[11px] text-neutral-600 dark:text-neutral-300">
                <span
                  v-for="slice in insight.severityBreakdown"
                  :key="slice.key"
                  class="inline-flex items-center gap-1 rounded-full border border-neutral-200 bg-white/80 px-2 py-0.5 dark:border-neutral-700 dark:bg-neutral-900/50"
                >
                  <span
                    class="h-2 w-2 rounded-full"
                    :class="severityDotClassMap[slice.color] ?? severityDotClassMap.neutral"
                  />
                  {{ slice.label }} {{ slice.count.toLocaleString() }}
                </span>
              </div>
            </div>

            <div class="space-y-1">
              <div class="flex h-10 items-end gap-1">
                <div
                  v-for="point in insight.trend"
                  :key="`${insight.product.productKey}-${point.label}`"
                  class="w-2 rounded-t bg-primary-500/60 dark:bg-primary-400/60"
                  :style="{ height: computeSparkHeight(point.count, getTrendMax(insight.trend)) }"
                />
              </div>
              <div class="flex justify-between text-[10px] text-neutral-400 dark:text-neutral-500">
                <span>{{ insight.trend[0]?.label ?? '—' }}</span>
                <span>{{ insight.trend[insight.trend.length - 1]?.label ?? '—' }}</span>
              </div>
            </div>
          </div>
        </div>

        <div
          v-else
          class="rounded-lg border border-dashed border-neutral-200 p-4 text-sm text-neutral-500 dark:border-neutral-700 dark:text-neutral-400"
        >
          No tracked entries within the current catalog window yet. As soon as new
          CVEs land for your software, they will appear here with trend context.
        </div>

        <div class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
          <button
            type="button"
            class="transition hover:text-neutral-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:hover:text-neutral-200"
            @click="emits('clear')"
          >
            Clear all tracked products
          </button>
          <span>{{ props.trackedProductCount.toLocaleString() }} tracked</span>
        </div>
      </div>

      <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
        You haven’t selected any products yet. Use the settings page to search the
        catalog and build your watch list.
      </p>

      <UAlert
        v-if="props.saveError"
        color="error"
        variant="soft"
        icon="i-lucide-alert-triangle"
        :description="props.saveError"
      />
    </div>
  </UCard>
</template>
