<script setup lang="ts">
import { computed } from 'vue'
import { useElementSize } from '@vueuse/core'
import { VisArea, VisAxis, VisCrosshair, VisLine, VisTooltip, VisXYContainer } from '@unovis/vue'

type TrendDatum = {
  period: string
  value: number
  share: number
}

const props = defineProps<{
  items: { period: string; value: number }[]
  title?: string
}>()

const containerRef = useTemplateRef<HTMLElement | null>('containerRef')
const { width } = useElementSize(containerRef)

const total = computed(() =>
  props.items.reduce((sum, item) => sum + (Number.isFinite(item.value) ? item.value : 0), 0)
)

const data = computed<TrendDatum[]>(() => {
  const sum = total.value
  if (!sum) {
    return props.items.map(item => ({ period: item.period, value: item.value, share: 0 }))
  }

  return props.items.map(item => ({
    period: item.period,
    value: item.value,
    share: item.value ? (item.value / sum) * 100 : 0
  }))
})

const formatNumber = new Intl.NumberFormat('en', { maximumFractionDigits: 0 }).format
const formatPercent = new Intl.NumberFormat('en', { maximumFractionDigits: 1 }).format

const x = (_: TrendDatum, index: number) => index
const y = (d: TrendDatum) => d.value

const xTicks = (index: number) => {
  if (!data.value.length || index < 0 || index >= data.value.length) {
    return ''
  }

  if (index === 0 || index === data.value.length - 1) {
    return ''
  }

  return data.value[index]?.period ?? ''
}

const tooltipTemplate = (datum: TrendDatum) => {
  const valueLabel = formatNumber(datum.value)
  const percentLabel = formatPercent(datum.share)
  return `${datum.period}: ${valueLabel} KEVs (${percentLabel}%)`
}

const heightClass = 'h-72'
</script>

<template>
  <UCard>
    <template #header>
      <strong>{{ props.title ?? 'Monthly trend' }}</strong>
    </template>
    <template #body>
      <div ref="containerRef" class="w-full">
        <VisXYContainer :data="data" :width="width" :class="['trend-chart', heightClass]" :padding="{ top: 40 }">
          <VisLine :x="x" :y="y" color="var(--chart-exploit-color)" />
          <VisArea :x="x" :y="y" color="var(--chart-exploit-color)" :opacity="0.12" />
          <VisAxis type="x" :x="x" :tick-format="xTicks" />
          <VisCrosshair color="var(--chart-exploit-color)" :template="tooltipTemplate" />
          <VisTooltip />
        </VisXYContainer>
      </div>
    </template>
  </UCard>
</template>

<style scoped>
.trend-chart {
  --vis-crosshair-line-stroke-color: var(--chart-exploit-color);
  --vis-crosshair-circle-stroke-color: var(--ui-bg);
  --vis-axis-grid-color: var(--ui-border);
  --vis-axis-tick-color: var(--ui-border);
  --vis-axis-tick-label-color: var(--ui-text-dimmed);
  --vis-tooltip-background-color: var(--ui-bg);
  --vis-tooltip-border-color: var(--ui-border);
  --vis-tooltip-text-color: var(--ui-text-highlighted);
}
</style>
