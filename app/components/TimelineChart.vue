<script setup lang="ts">
import { parseISO } from 'date-fns'
import { useElementSize } from '@vueuse/core'
import { computed, useTemplateRef } from 'vue'
import { VisArea, VisAxis, VisCrosshair, VisLine, VisTooltip, VisXYContainer } from '@unovis/vue'
import type { KevTimelineBucket, Period, Range } from '~/types'

type DataRecord = { date: Date; amount: number }

type Props = {
  buckets: KevTimelineBucket[]
  period: Period
  range: Range | null
  height?: string
  paddingTop?: number
}

const props = defineProps<Props>()

const containerRef = useTemplateRef<HTMLElement | null>('containerRef')
const { width } = useElementSize(containerRef)

const data = computed<DataRecord[]>(() => {
  const records = props.buckets
    .map((bucket) => {
      const date = parseISO(bucket.date)
      if (Number.isNaN(date.getTime())) {
        return null
      }

      return { date, amount: bucket.count }
    })
    .filter((item): item is DataRecord => item !== null)

  records.sort((a, b) => a.date.getTime() - b.date.getTime())

  return records
})

const formatNumber = new Intl.NumberFormat('en', { maximumFractionDigits: 0 }).format

const displayDate = (date: Date): string =>
  ({
    daily: date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    weekly: date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    monthly: date.toLocaleDateString(undefined, { month: 'short', year: 'numeric' })
  } as const)[props.period]

const x = (_: DataRecord, index: number) => index
const y = (d: DataRecord) => d.amount

const xTicks = (index: number) => {
  if (index === 0 || index === data.value.length - 1 || !data.value[index]) {
    return ''
  }

  return displayDate(data.value[index].date)
}

const template = (datum: DataRecord) => `${displayDate(datum.date)}: ${formatNumber(datum.amount)}`

const paddingTop = computed(() => props.paddingTop ?? 40)

const heightClass = computed(() => props.height ?? 'h-80')

const total = computed(() => data.value.reduce((sum, item) => sum + item.amount, 0))

defineExpose({ total })
</script>

<template>
  <div ref="containerRef" class="w-full">
    <VisXYContainer :data="data" :padding="{ top: paddingTop }" :width="width" :class="heightClass">
      <VisLine :x="x" :y="y" color="var(--ui-primary)" />
      <VisArea :x="x" :y="y" color="var(--ui-primary)" :opacity="0.1" />
      <VisAxis type="x" :x="x" :tick-format="xTicks" />
      <VisCrosshair color="var(--ui-primary)" :template="template" />
      <VisTooltip />
    </VisXYContainer>
  </div>
</template>

<style scoped>
.unovis-xy-container {
  --vis-crosshair-line-stroke-color: var(--ui-primary);
  --vis-crosshair-circle-stroke-color: var(--ui-bg);
  --vis-axis-grid-color: var(--ui-border);
  --vis-axis-tick-color: var(--ui-border);
  --vis-axis-tick-label-color: var(--ui-text-dimmed);
  --vis-tooltip-background-color: var(--ui-bg);
  --vis-tooltip-border-color: var(--ui-border);
  --vis-tooltip-text-color: var(--ui-text-highlighted);
}
</style>
