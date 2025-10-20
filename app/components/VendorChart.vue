<script setup lang="ts">
import { computed } from 'vue'
import { useElementSize } from '@vueuse/core'
import { VisAxis, VisBar, VisCrosshair, VisTooltip, VisXYContainer } from '@unovis/vue'

type VendorDatum = {
  label: string
  value: number
  share: number
}

const props = defineProps<{
  items: { label: string; value: number }[]
  total: number
  title?: string
}>()

const containerRef = useTemplateRef<HTMLElement | null>('containerRef')
const { width } = useElementSize(containerRef)

const total = computed(() => {
  if (props.total > 0) {
    return props.total
  }

  return props.items.reduce((sum, item) => sum + (Number.isFinite(item.value) ? item.value : 0), 0)
})

const data = computed<VendorDatum[]>(() => {
  const sum = total.value
  if (!sum) {
    return props.items.map(item => ({ label: item.label, value: item.value, share: 0 }))
  }

  return props.items.map(item => ({
    label: item.label,
    value: item.value,
    share: item.value ? (item.value / sum) * 100 : 0
  }))
})

const formatNumber = new Intl.NumberFormat('en', { maximumFractionDigits: 0 }).format
const formatPercent = new Intl.NumberFormat('en', { maximumFractionDigits: 1 }).format

const x = (_: VendorDatum, index: number) => index
const y = (d: VendorDatum) => d.value

const xTicks = (index: number) => data.value[index]?.label ?? ''

const yTicks = (value: number | string) => {
  const numeric = typeof value === 'number' ? value : Number.parseFloat(String(value))
  if (!Number.isFinite(numeric)) {
    return ''
  }

  return formatNumber(numeric)
}

const tooltipTemplate = (datum: VendorDatum) => {
  const valueLabel = formatNumber(datum.value)
  const percentLabel = formatPercent(datum.share)
  return `${datum.label}: ${valueLabel} KEVs (${percentLabel}%)`
}

const heightClass = 'h-72'
</script>

<template>
  <UCard>
    <template #header>
      <strong>{{ props.title ?? 'Top Vendors' }}</strong>
    </template>
    <template #body>
      <div ref="containerRef" class="w-full">
        <VisXYContainer :data="data" :width="width" :class="['vendor-chart', heightClass]" :padding="{ top: 32, left: 16, right: 16 }">
          <VisBar :x="x" :y="y" color="var(--chart-domain-color)" />
          <VisAxis type="x" :x="x" :tick-format="xTicks" />
          <VisAxis type="y" :y="y" :tick-format="yTicks" />
          <VisCrosshair color="var(--chart-domain-color)" :template="tooltipTemplate" />
          <VisTooltip />
        </VisXYContainer>
      </div>
    </template>
  </UCard>
</template>

<style scoped>
.vendor-chart {
  --vis-crosshair-line-stroke-color: var(--chart-domain-color);
  --vis-crosshair-circle-stroke-color: var(--ui-bg);
  --vis-axis-grid-color: var(--ui-border);
  --vis-axis-tick-color: var(--ui-border);
  --vis-axis-tick-label-color: var(--ui-text-dimmed);
  --vis-tooltip-background-color: var(--ui-bg);
  --vis-tooltip-border-color: var(--ui-border);
  --vis-tooltip-text-color: var(--ui-text-highlighted);
}
</style>
