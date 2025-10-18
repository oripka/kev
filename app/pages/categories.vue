<script setup lang="ts">
import { computed, h, reactive, ref, resolveComponent } from 'vue'
import { format, parseISO } from 'date-fns'
import type { TableColumn } from '@nuxt/ui'
import { useKevData } from '~/composables/useKevData'
import type { KevEntry } from '~/types'

const {
  entries,
  domainCategories,
  vulnerabilityCategories,
  categoryNames,
  vulnerabilityTypeNames
} = useKevData()

const filters = reactive({
  domain: null as string | null,
  vulnerability: null as string | null,
  text: ''
})

const domainOptions = computed(() => {
  const counts = new Map(domainCategories.value.map(item => [item.name, item.count]))
  return categoryNames.value.map(name => ({
    label: counts.has(name) ? `${name} (${counts.get(name)})` : name,
    value: name
  }))
})

const vulnerabilityOptions = computed(() => {
  const counts = new Map(vulnerabilityCategories.value.map(item => [item.name, item.count]))
  return vulnerabilityTypeNames.value.map(name => ({
    label: counts.has(name) ? `${name} (${counts.get(name)})` : name,
    value: name
  }))
})

const UBadge = resolveComponent('UBadge')

const results = computed(() => {
  const term = filters.text.trim().toLowerCase()

  return entries.value.filter(entry => {
    if (filters.domain && !entry.domainCategories.includes(filters.domain as typeof entry.domainCategories[number])) {
      return false
    }

    if (
      filters.vulnerability &&
      !entry.vulnerabilityCategories.includes(filters.vulnerability as typeof entry.vulnerabilityCategories[number])
    ) {
      return false
    }

    if (term) {
      const text = `${entry.cveId} ${entry.vendor} ${entry.product} ${entry.vulnerabilityName}`.toLowerCase()
      if (!text.includes(term)) {
        return false
      }
    }

    return true
  })
})

const columns: TableColumn<KevEntry>[] = [
  { accessorKey: 'cveId', header: 'CVE' },
  { accessorKey: 'vendor', header: 'Vendor' },
  { accessorKey: 'product', header: 'Product' },
  {
    accessorKey: 'dateAdded',
    header: 'Date added',
    cell: ({ row }) => {
      const parsed = parseISO(row.original.dateAdded)
      return Number.isNaN(parsed.getTime()) ? row.original.dateAdded : format(parsed, 'yyyy-MM-dd')
    }
  },
  {
    id: 'domain',
    header: 'Domain',
    cell: ({ row }) =>
      h(
        'div',
        { class: 'flex flex-wrap gap-2' },
        row.original.domainCategories.map(category =>
          h(
            UBadge,
            { color: 'primary', variant: 'soft' },
            () => category
          )
        )
      )
  },
  {
    id: 'type',
    header: 'Type',
    cell: ({ row }) =>
      h(
        'div',
        { class: 'flex flex-wrap gap-2' },
        row.original.vulnerabilityCategories.map(category =>
          h(
            UBadge,
            { color: 'secondary', variant: 'soft' },
            () => category
          )
        )
      )
  }
]
</script>

<template>
  <UPage>
    <UPageHeader
      title="Category explorer"
      description="Combine domain and vulnerability categories to focus on what matters"
    />

    <UPageBody>
      <UPageSection>
        <UCard>
          <template #header>
            <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
              Filters
            </p>
          </template>

          <div class="space-y-4">
            <UFormField label="Domain category">
              <USelectMenu v-model="filters.domain" :options="domainOptions" clearable searchable />
            </UFormField>

            <UFormField label="Vulnerability category">
              <USelectMenu v-model="filters.vulnerability" :options="vulnerabilityOptions" clearable searchable />
            </UFormField>

            <UFormField label="Search">
              <UInput v-model="filters.text" placeholder="Filter by CVE, vendor, or product" />
            </UFormField>

            <UAlert
              v-if="filters.domain || filters.vulnerability || filters.text"
              color="info"
              variant="soft"
              icon="i-lucide-filters"
              :title="`${results.length} matching vulnerabilities`"
            />
          </div>
        </UCard>
      </UPageSection>

      <UPageSection>
        <UCard>
          <template #header>
            <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
              Results
            </p>
          </template>

          <UTable :data="results" :columns="columns" />
        </UCard>
      </UPageSection>
    </UPageBody>
  </UPage>
</template>
