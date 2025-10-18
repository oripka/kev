<script setup lang="ts">
import { computed, ref } from 'vue'
import { format, parseISO, subDays, subMonths, subYears } from 'date-fns'
import { useKevData } from '~/composables/useKevData'
import KevTimelineCard from '~/components/KevTimelineCard.vue'
import type { Period, Range } from '~/types'

const {
  entries,
  total,
  vendorTotal,
  productTotal,
  ransomwareCount,
  lastAddedDate,
  earliestDate,
  updatedAt,
  pending
} = useKevData()

const numberFormatter = new Intl.NumberFormat('en', { maximumFractionDigits: 0 })

const summaryCards = computed(() => [
  {
    title: 'Catalog entries',
    value: numberFormatter.format(total.value)
  },
  {
    title: 'Vendors represented',
    value: numberFormatter.format(vendorTotal.value)
  },
  {
    title: 'Products impacted',
    value: numberFormatter.format(productTotal.value)
  },
  {
    title: 'Known ransomware links',
    value: numberFormatter.format(ransomwareCount.value)
  }
])

const period = ref<Period>('monthly')

const rangePreset = ref('1y')

const rangeOptions = [
  { label: 'Last 90 days', value: '90d' },
  { label: 'Last 6 months', value: '6m' },
  { label: 'Last year', value: '1y' },
  { label: 'All data', value: 'all' }
]

const updatedLabel = computed(() => {
  if (!updatedAt.value) {
    return 'Awaiting first sync'
  }

  const parsed = parseISO(updatedAt.value)
  if (Number.isNaN(parsed.getTime())) {
    return 'Awaiting first sync'
  }

  return `Last synced ${format(parsed, 'PPpp')}`
})

const resolveRange = (): Range => {
  const end = lastAddedDate.value ?? new Date()
  const earliest = earliestDate.value ?? end

  let start: Date

  switch (rangePreset.value) {
    case '90d':
      start = subDays(end, 89)
      break
    case '6m':
      start = subMonths(end, 6)
      break
    case 'all':
      start = earliest
      break
    case '1y':
    default:
      start = subYears(end, 1)
      break
  }

  if (start < earliest) {
    start = earliest
  }

  return {
    start,
    end
  }
}

const range = computed<Range>(() => resolveRange())
</script>

<template>
  <UPage>
    <UPageHeader
      title="KEV Overview"
      :description="updatedLabel"
    />

  <UPageBody>
      <UPageSection>
        <USkeleton v-if="pending" class="h-24" />
        <template v-else>
          <UPageGrid>
            <UCard v-for="card in summaryCards" :key="card.title">
              <template #header>
                <UText size="sm" color="neutral">
                  {{ card.title }}
                </UText>
              </template>
              <UText size="3xl" weight="semibold">
                {{ card.value }}
              </UText>
            </UCard>
          </UPageGrid>
        </template>
      </UPageSection>

      <UPageSection>
        <UCard>
          <template #header>
            <div>
              <UText size="lg" weight="semibold">
                Activity trend
              </UText>
            </div>
          </template>

          <template #default>
            <div class="space-y-4">
              <UFormGroup label="Period">
                <USelectMenu v-model="period" :options="[
                  { label: 'Daily', value: 'daily' },
                  { label: 'Weekly', value: 'weekly' },
                  { label: 'Monthly', value: 'monthly' }
                ]" />
              </UFormGroup>
              <UFormGroup label="Range">
                <USelectMenu v-model="rangePreset" :options="rangeOptions" />
              </UFormGroup>
              <KevTimelineCard :entries="entries" :period="period" :range="range" />
            </div>
          </template>
        </UCard>
      </UPageSection>
    </UPageBody>
  </UPage>
</template>
