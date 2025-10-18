<script setup lang="ts">
import type { KevFilterState } from '~/types'

const props = defineProps<{
  filters: KevFilterState
  vendors: string[]
  products: string[]
  categories: string[]
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
const setVulnerabilityType = (value: unknown) => update({ vulnerabilityType: coerceNullableString(value) })
const setRansomwareOnly = (value: boolean | 'indeterminate') => update({ ransomwareOnly: value === true })
</script>

<template>
  <UCard>
    <template #header>
      <strong>Filters</strong>
    </template>
    <template #body>
      <UForm>
        <UFormField label="Search">
          <UInput
            :model-value="props.filters.search"
            placeholder="Search by CVE, vendor, or product"
            @update:model-value="(value) => update({ search: value })"
          />
        </UFormField>
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
