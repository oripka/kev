<script setup lang="ts">
import { computed } from 'vue'
import type { KevTimelineBucket, Period, Range } from '~/types'

const props = defineProps<{
  period: Period
  range: Range
  buckets: KevTimelineBucket[]
}>()

const formatNumber = new Intl.NumberFormat('en', { maximumFractionDigits: 0 }).format

const total = computed(() =>
  props.buckets.reduce((sum, bucket) => sum + bucket.count, 0)
)
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
      :buckets="props.buckets"
      :period="props.period"
      :range="props.range"
      height="h-96"
    />
  </UCard>
</template>
