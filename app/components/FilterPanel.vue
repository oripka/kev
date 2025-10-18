<script setup lang="ts">
import { computed } from 'vue'
import type { KevFilterState } from '~/types'

const props = defineProps<{
  filters: KevFilterState
  vendors: string[]
  products: string[]
  categories: string[]
  exploitLayers: string[]
  vulnerabilityTypes: string[]
}>()

const emit = defineEmits<{
  (event: 'update:filters', value: KevFilterState): void
  (event: 'reset'): void
}>()

function update(partial: Partial<KevFilterState>) {
  emit('update:filters', { ...props.filters, ...partial })
}

function reset() {
  emit('reset')
}

const coerceNullableString = (value: unknown) => {
  return typeof value === 'string' && value.length ? value : null
}

const setVendor = (value: unknown) => update({ vendor: coerceNullableString(value) })
const setProduct = (value: unknown) => update({ product: coerceNullableString(value) })
const setCategory = (value: unknown) => update({ category: coerceNullableString(value) })
const setExploitLayer = (value: unknown) => update({ exploitLayer: coerceNullableString(value) })
const setVulnerabilityType = (value: unknown) => update({ vulnerabilityType: coerceNullableString(value) })
const setRansomwareOnly = (value: boolean | 'indeterminate') => update({ ransomwareOnly: value === true })
const setWellKnownOnly = (value: boolean) => update({ wellKnownOnly: value })
const setSource = (value: unknown) => {
  if (value === 'kev' || value === 'enisa') {
    update({ source: value })
  } else {
    update({ source: 'all' })
  }
}

const CVSS_MIN = 0
const CVSS_MAX = 10
const defaultCvssRange = [CVSS_MIN, CVSS_MAX] as const
const EPSS_MIN = 0
const EPSS_MAX = 100
const defaultEpssRange = [EPSS_MIN, EPSS_MAX] as const

const sliderRange = computed<[number, number]>(() => {
  const value = props.filters.cvssRange
  if (Array.isArray(value) && value.length === 2) {
    const [from, to] = value as [number, number]
    return [
      Number.isFinite(from) ? from : defaultCvssRange[0],
      Number.isFinite(to) ? to : defaultCvssRange[1]
    ]
  }
  return [defaultCvssRange[0], defaultCvssRange[1]]
})

const clampCvss = (value: unknown) => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.min(CVSS_MAX, Math.max(CVSS_MIN, value))
  }

  const parsed = Number.parseFloat(String(value))
  if (Number.isNaN(parsed)) {
    return CVSS_MIN
  }
  return Math.min(CVSS_MAX, Math.max(CVSS_MIN, parsed))
}

const normaliseCvssRange = (value: number | number[]): [number, number] => {
  if (Array.isArray(value)) {
    const [start = CVSS_MIN, end = CVSS_MAX] = value
    const first = clampCvss(start)
    const second = clampCvss(end)
    return first <= second ? [first, second] : [second, first]
  }

  const score = clampCvss(value)
  return [score, score]
}

const setCvssRange = (value: number | number[]) => {
  const [start, end] = normaliseCvssRange(value)
  const isDefault = start === defaultCvssRange[0] && end === defaultCvssRange[1]
  update({ cvssRange: isDefault ? null : [start, end] })
}

const epssSliderRange = computed<[number, number]>(() => {
  const value = props.filters.epssRange
  if (Array.isArray(value) && value.length === 2) {
    const [from, to] = value as [number, number]
    return [
      Number.isFinite(from) ? from : defaultEpssRange[0],
      Number.isFinite(to) ? to : defaultEpssRange[1]
    ]
  }
  return [defaultEpssRange[0], defaultEpssRange[1]]
})

const clampEpss = (value: unknown) => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.min(EPSS_MAX, Math.max(EPSS_MIN, value))
  }

  const parsed = Number.parseFloat(String(value))
  if (Number.isNaN(parsed)) {
    return EPSS_MIN
  }
  return Math.min(EPSS_MAX, Math.max(EPSS_MIN, parsed))
}

const normaliseEpssRange = (value: number | number[]): [number, number] => {
  if (Array.isArray(value)) {
    const [start = EPSS_MIN, end = EPSS_MAX] = value
    const first = clampEpss(start)
    const second = clampEpss(end)
    return first <= second ? [first, second] : [second, first]
  }

  const score = clampEpss(value)
  return [score, score]
}

const setEpssRange = (value: number | number[]) => {
  const [start, end] = normaliseEpssRange(value)
  const isDefault = start === defaultEpssRange[0] && end === defaultEpssRange[1]
  update({ epssRange: isDefault ? null : [start, end] })
}

const formatCvss = (score: number) => score.toFixed(1).replace(/\.0$/, '')
const isCvssFiltered = computed(
  () => Array.isArray(props.filters.cvssRange) && props.filters.cvssRange.length === 2
)
const cvssRangeLabel = computed(() =>
  isCvssFiltered.value
    ? `${formatCvss(sliderRange.value[0])} – ${formatCvss(sliderRange.value[1])}`
    : 'All scores'
)

const formatEpssLabel = (score: number) => score.toFixed(0)
const isEpssFiltered = computed(
  () => Array.isArray(props.filters.epssRange) && props.filters.epssRange.length === 2
)
const epssRangeLabel = computed(() =>
  isEpssFiltered.value
    ? `${formatEpssLabel(epssSliderRange.value[0])} – ${formatEpssLabel(epssSliderRange.value[1])}`
    : 'All scores'
)

const sourceOptions = [
  { label: 'All sources', value: 'all' },
  { label: 'CISA KEV', value: 'kev' },
  { label: 'ENISA', value: 'enisa' }
]
</script>

<template>
  <UCard>
    <template #header>
      <strong>Filters</strong>
    </template>
    <template #body>
      <UForm>
        <div class="flex flex-col gap-4 lg:flex-row">
          <UFormField label="Search" class="lg:flex-1">
            <UInput
              :model-value="props.filters.search"
              placeholder="Search by CVE, vendor, product, or description"
              @update:model-value="(value) => update({ search: value })"
            />
          </UFormField>
          <UFormField label="CVSS score" class="lg:flex-1">
            <div class="flex items-center gap-3">
              <USlider
                class="flex-1"
                :model-value="sliderRange"
                :min="CVSS_MIN"
                :max="CVSS_MAX"
                :step="0.1"
                :min-steps-between-thumbs="1"
                tooltip
                @update:model-value="setCvssRange"
              />
              <span class="w-20 text-right text-sm text-neutral-600 dark:text-neutral-300">
                {{ cvssRangeLabel }}
              </span>
            </div>
          </UFormField>
        </div>
        <div class="flex flex-col gap-4 lg:flex-row">
          <UFormField label="Source" class="lg:flex-1">
            <USelect
              :model-value="props.filters.source"
              :options="sourceOptions"
              @update:model-value="setSource"
            />
          </UFormField>
          <UFormField label="EPSS score" class="lg:flex-1">
            <div class="flex items-center gap-3">
              <USlider
                class="flex-1"
                :model-value="epssSliderRange"
                :min="EPSS_MIN"
                :max="EPSS_MAX"
                :step="1"
                :min-steps-between-thumbs="1"
                tooltip
                @update:model-value="setEpssRange"
              />
              <span class="w-20 text-right text-sm text-neutral-600 dark:text-neutral-300">
                {{ epssRangeLabel }}
              </span>
            </div>
          </UFormField>
        </div>
        <UFormField label="Vendor">
          <USelect
            :model-value="props.filters.vendor"
            :options="props.vendors"
            placeholder="All vendors"
            @update:model-value="setVendor"
            clearable
          />
        </UFormField>
        <UFormField label="Product">
          <USelect
            :model-value="props.filters.product"
            :options="props.products"
            placeholder="All products"
            @update:model-value="setProduct"
            clearable
          />
        </UFormField>
        <UFormField label="Category">
          <USelect
            :model-value="props.filters.category"
            :options="props.categories"
            placeholder="All categories"
            @update:model-value="setCategory"
            clearable
          />
        </UFormField>
        <UFormField label="Exploit profile">
          <USelect
            :model-value="props.filters.exploitLayer"
            :options="props.exploitLayers"
            placeholder="All profiles"
            @update:model-value="setExploitLayer"
            clearable
          />
        </UFormField>
        <UFormField label="Vulnerability type">
          <USelect
            :model-value="props.filters.vulnerabilityType"
            :options="props.vulnerabilityTypes"
            placeholder="All types"
            @update:model-value="setVulnerabilityType"
            clearable
          />
        </UFormField>
        <UFormField>
          <UCheckbox
            :model-value="props.filters.ransomwareOnly"
            label="Only show ransomware-linked KEVs"
            @update:model-value="setRansomwareOnly"
          />
        </UFormField>
        <UFormField label="Well-known focus">
          <div class="flex items-center justify-between gap-3">
            <span class="text-sm text-neutral-600 dark:text-neutral-300">
              Only show named, high-profile CVEs
            </span>
            <USwitch :model-value="props.filters.wellKnownOnly" @update:model-value="setWellKnownOnly" />
          </div>
        </UFormField>
        <UFormField label="Added after">
          <UInput
            type="date"
            :model-value="props.filters.startDate"
            @update:model-value="(value) => update({ startDate: value })"
          />
        </UFormField>
        <UFormField label="Added before">
          <UInput
            type="date"
            :model-value="props.filters.endDate"
            @update:model-value="(value) => update({ endDate: value })"
          />
        </UFormField>
      </UForm>
    </template>
    <template #footer>
      <UButton color="neutral" variant="outline" @click="reset">Reset filters</UButton>
    </template>
  </UCard>
</template>
