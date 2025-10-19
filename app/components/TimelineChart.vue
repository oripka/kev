<script setup lang="ts">
import {
  eachDayOfInterval,
  eachMonthOfInterval,
  eachWeekOfInterval,
  format,
  isWithinInterval,
  parseISO,
  startOfDay,
  startOfMonth,
  startOfWeek
} from 'date-fns'
import { useElementSize } from '@vueuse/core'
import { computed, ref, watch } from 'vue'
import { VisArea, VisAxis, VisCrosshair, VisLine, VisTooltip, VisXYContainer } from '@unovis/vue'
import type { KevEntry, Period, Range } from '~/types'

type DataRecord = { date: Date; amount: number }

type Props = {
  entries: KevEntry[]
  period: Period
  range: Range | null
  height?: string
  paddingTop?: number
}

const props = defineProps<Props>()

const containerRef = useTemplateRef<HTMLElement | null>('containerRef')
const { width } = useElementSize(containerRef)

const data = ref<DataRecord[]>([])

const weekOptions = { weekStartsOn: 1 as const }

const generators: Record<Period, typeof eachDayOfInterval> = {
  daily: eachDayOfInterval,
  weekly: eachWeekOfInterval as unknown as typeof eachDayOfInterval,
  monthly: eachMonthOfInterval as unknown as typeof eachDayOfInterval
}

const aligners: Record<Period, (date: Date) => Date> = {
  daily: startOfDay,
  weekly: date => startOfWeek(date, weekOptions),
  monthly: startOfMonth
}

const keyFormats: Record<Period, string> = {
  daily: 'yyyy-MM-dd',
  weekly: 'yyyy-MM-dd',
  monthly: 'yyyy-MM'
}

watch(
  () => [props.period, props.range?.start?.getTime() ?? null, props.range?.end?.getTime() ?? null, props.entries],
  () => {
    const { range } = props
    if (!range?.start || !range?.end) {
      data.value = []
      return
    }

    const generator = generators[props.period]
    const align = aligners[props.period]
    const keyFormat = keyFormats[props.period]

    const interval = { start: range.start, end: range.end }
    const dates = props.period === 'weekly'
      ? (eachWeekOfInterval(interval, weekOptions) as Date[])
      : generator(interval)

    const buckets = dates.map(date => ({ date, amount: 0 }))
    const indexByKey = new Map<string, number>()

    buckets.forEach((bucket, index) => {
      indexByKey.set(format(align(bucket.date), keyFormat), index)
    })

    for (const entry of props.entries) {
      const parsed = parseISO(entry.dateAdded)
      if (Number.isNaN(parsed.getTime())) {
        continue
      }

      if (!isWithinInterval(parsed, interval)) {
        continue
      }

      const aligned = align(parsed)
      const key = format(aligned, keyFormat)
      const index = indexByKey.get(key)
      if (index === undefined) {
        continue
      }

      const bucket = buckets[index]
      if (!bucket) {
        continue
      }

      bucket.amount += 1
    }

    data.value = buckets
  },
  { immediate: true }
)

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
