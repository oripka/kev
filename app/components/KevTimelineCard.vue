<script setup lang="ts">
import type { KevEntrySummary, Period, Range } from '~/types'

const props = defineProps<{
  period: Period
  range: Range
  entries: KevEntrySummary[]
}>()

const chartRef = useTemplateRef<InstanceType<typeof TimelineChart> | null>('chartRef')

const total = computed(() => chartRef.value?.total.value ?? 0)

const formatNumber = new Intl.NumberFormat('en', { maximumFractionDigits: 0 }).format
</script>

<template>
  <UCard :ui="{ root: 'overflow-visible', body: '!px-0 !pt-0 !pb-3' }">
    <template #header>
      <div>
        <p class="text-xs text-neutral-500 dark:text-neutral-400">
          Activity in range
        </p>
        <p class="text-3xl font-semibold text-neutral-900 dark:text-neutral-50">
          {{ formatNumber(total) }}
        </p>
      </div>
    </template>

    <TimelineChart
      ref="chartRef"
      :entries="props.entries"
      :period="props.period"
      :range="props.range"
      height="h-96"
    />
  </UCard>
</template>
