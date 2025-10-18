<script setup lang="ts">
import type { KevFilterState } from '~/types/kev'

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
            @update:model-value="(value) => update({ vendor: value })"
            clearable
          />
        </UFormField>
        <UFormField label="Product">
          <USelect
            :model-value="props.filters.product"
            :options="props.products"
            placeholder="All products"
            @update:model-value="(value) => update({ product: value })"
            clearable
          />
        </UFormField>
        <UFormField label="Category">
          <USelect
            :model-value="props.filters.category"
            :options="props.categories"
            placeholder="All categories"
            @update:model-value="(value) => update({ category: value })"
            clearable
          />
        </UFormField>
        <UFormField label="Vulnerability type">
          <USelect
            :model-value="props.filters.vulnerabilityType"
            :options="props.vulnerabilityTypes"
            placeholder="All types"
            @update:model-value="(value) => update({ vulnerabilityType: value })"
            clearable
          />
        </UFormField>
        <UFormField>
          <UCheckbox
            :model-value="props.filters.ransomwareOnly"
            label="Only show ransomware-linked KEVs"
            @update:model-value="(value) => update({ ransomwareOnly: value ?? false })"
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
