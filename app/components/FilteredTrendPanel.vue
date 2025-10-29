<script setup lang="ts">
import { differenceInDays, parseISO } from 'date-fns'
import { computed } from 'vue'
import type { KevTimeline, Period, Range } from '~/types'
import TimelineChart from './TimelineChart.vue'

const props = defineProps<{ timeline: KevTimeline }>()

const show = defineModel<boolean>({ default: false })

const validRange = computed<Range | null>(() => {
  const range = props.timeline.range
  if (!range) {
    return null
  }

  const start = parseISO(range.start)
  const end = parseISO(range.end)
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return null
  }

  return { start, end }
})

const period = computed<Period>(() => {
  const range = validRange.value
  if (!range) {
    return 'monthly'
  }

  const span = Math.max(1, differenceInDays(range.end, range.start))
  if (span <= 45) {
    return 'daily'
  }
  if (span <= 540) {
    return 'weekly'
  }
  return 'monthly'
})

const periodBuckets = computed(() => props.timeline.buckets[period.value] ?? [])

const totalEntries = computed(() =>
  periodBuckets.value.reduce((sum, bucket) => sum + bucket.count, 0)
)

const periodLabel = computed(() => {
  const value = period.value
  return value === 'daily' ? 'Daily' : value === 'weekly' ? 'Weekly' : 'Monthly'
})

const hasData = computed(() => Boolean(validRange.value) && periodBuckets.value.length > 0)

const totalFormatter = new Intl.NumberFormat('en-US')
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="space-y-1">
          <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
            Trend explorer
          </p>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Visualise how the filtered vulnerabilities accumulate over time.
          </p>
        </div>
        <div class="flex items-center gap-2">
          <USwitch v-model="show" aria-label="Toggle trend chart" />
          <div class="flex flex-col text-right leading-tight">
            <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
              Show trend lines
            </span>
            <span class="text-xs text-neutral-500 dark:text-neutral-400">
              {{ show ? 'Chart visible' : 'Chart hidden' }}
            </span>
          </div>
        </div>
      </div>
    </template>

    <div v-if="show" class="space-y-3">
      <div v-if="hasData" class="space-y-3">
        <p class="text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
          {{ periodLabel }} cadence · {{ totalFormatter.format(totalEntries) }} CVEs
        </p>
        <TimelineChart :buckets="periodBuckets" :period="period" :range="validRange" />
      </div>
      <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
        Not enough timeline information is available for the current selection.
      </p>
    </div>
    <div v-else class="text-sm text-neutral-500 dark:text-neutral-400">
      Use the switch above to reveal a Unovis line chart for the vulnerabilities in scope.
    </div>
  </UCard>
</template>
