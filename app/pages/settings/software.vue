<script setup lang="ts">
import { computed, h, onMounted, ref, resolveComponent, watch } from 'vue'
import { useDebounceFn } from '@vueuse/core'
import type { TableColumn } from '@nuxt/ui'
import type { CatalogSource, ProductCatalogItem, ProductCatalogResponse, TrackedProduct } from '~/types'
import { useTrackedProducts } from '~/composables/useTrackedProducts'

const sourceLabels: Record<CatalogSource, string> = {
  kev: 'CISA KEV',
  enisa: 'ENISA'
}

const searchTerm = ref('')
const debouncedSearch = ref('')
const updateSearch = useDebounceFn((value: string) => {
  debouncedSearch.value = value.trim()
}, 250)

watch(searchTerm, value => updateSearch(value))

const showAllResults = ref(false)
const numberFormatter = new Intl.NumberFormat('en-US')

const isSearchActive = computed(() => debouncedSearch.value.length >= 2)
const effectiveLimit = computed(() => {
  if (!isSearchActive.value && !showAllResults.value) {
    return 15
  }
  return 150
})

const isTopLimited = computed(() => !showAllResults.value && !isSearchActive.value)

const { data: catalogData, pending: catalogPending, error: catalogError, refresh: refreshCatalog } = await useAsyncData(
  'product-catalog',
  () =>
    $fetch<ProductCatalogResponse>('/api/products', {
      query: {
        q: debouncedSearch.value || undefined,
        limit: effectiveLimit.value
      }
    }),
  {
    watch: [debouncedSearch, effectiveLimit]
  }
)

const catalogItems = computed(() => catalogData.value?.items ?? [])

const catalogRows = computed(() =>
  catalogItems.value.map(item => ({
    ...item,
    sourceSummary: item.sources.map(source => sourceLabels[source]).join(', ')
  }))
)

const {
  trackedProducts,
  trackedProductSet,
  addTrackedProduct,
  removeTrackedProduct,
  clearTrackedProducts,
  showOwnedOnly,
  setShowOwnedOnly,
  isSaving,
  saveError,
  sessionId,
  ensureSession
} = useTrackedProducts()

const trackedProductCount = computed(() => trackedProducts.value.length)

const isTracked = (productKey: string) => trackedProductSet.value.has(productKey)

const addItem = (item: ProductCatalogItem) => {
  if (isTracked(item.productKey)) {
    return
  }

  const product: TrackedProduct = {
    productKey: item.productKey,
    productName: item.productName,
    vendorKey: item.vendorKey,
    vendorName: item.vendorName
  }

  addTrackedProduct(product)
}

const removeItem = (productKey: string) => {
  if (!isTracked(productKey)) {
    return
  }
  removeTrackedProduct(productKey)
}

const sessionLabel = computed(() => sessionId.value ?? 'Not created yet')

onMounted(() => {
  if (!sessionId.value) {
    void ensureSession()
  }
})

const UButton = resolveComponent('UButton')

const columns = computed<TableColumn<(ProductCatalogItem & { sourceSummary: string })>[]>(() => {
  const trackedSet = trackedProductSet.value

  return [
    {
      accessorKey: 'productName',
      header: 'Product',
      cell: ({ row }) =>
        h(
          'div',
          {
            class: 'max-w-xs truncate',
            title: row.original.productName
          },
          row.original.productName
        )
    },
    {
      accessorKey: 'vendorName',
      header: 'Vendor',
      cell: ({ row }) => row.original.vendorName
    },
    {
      accessorKey: 'kevCount',
      header: 'KEV matches',
      cell: ({ row }) => numberFormatter.format(row.original.kevCount),
      meta: {
        align: 'end'
      }
    },
    {
      accessorKey: 'sourceSummary',
      header: 'Sources',
      cell: ({ row }) => row.original.sourceSummary
    },
    {
      id: 'actions',
      header: '',
      enableSorting: false,
      meta: {
        align: 'end'
      },
      cell: ({ row }) => {
        const tracked = trackedSet.has(row.original.productKey)

        return h(
          UButton,
          {
            color: tracked ? 'neutral' : 'primary',
            size: 'xs',
            disabled: tracked,
            onClick: () => addItem(row.original)
          },
          () => (tracked ? 'Tracked' : 'Add to focus')
        )
      }
    }
  ]
})
</script>

<template>
  <UPage>
    <UPageBody>
      <div class="mx-auto grid w-full max-w-6xl gap-4 px-6">
        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                  Focus configuration
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Search the catalog to build and maintain the list of products your organisation tracks.
                </p>
              </div>
              <div class="space-y-1 text-right">
                <p class="text-xs uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Session identifier
                </p>
                <p class="text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                  {{ sessionLabel }}
                </p>
              </div>
            </div>
          </template>

          <div class="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <div class="space-y-4">
              <div class="space-y-2">
                <UFormField label="Search the catalog" help="Type at least two characters to filter by product or vendor.">
                  <UInput v-model="searchTerm" placeholder="Search by product or vendor name" />
                </UFormField>
                <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div class="flex flex-wrap items-center gap-3 text-xs text-neutral-500 dark:text-neutral-400">
                    <span>
                      Showing {{ catalogRows.length }} results
                    </span>
                    <span v-if="isTopLimited" class="rounded-full bg-primary-100/60 px-2 py-1 text-[11px] font-semibold text-primary-700 dark:bg-primary-500/15 dark:text-primary-300">
                      Top 15 most exploited vulnerabilities
                    </span>
                  </div>
                  <div class="flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      class="text-xs font-medium text-primary-600 hover:underline dark:text-primary-400"
                      @click="refreshCatalog"
                    >
                      Refresh list
                    </button>
                    <label class="flex items-center gap-2 text-xs font-medium text-neutral-600 dark:text-neutral-300">
                      <USwitch
                        :model-value="showAllResults"
                        :disabled="isSearchActive"
                        aria-label="Toggle showing all catalog results"
                        @update:model-value="value => (showAllResults = value)"
                      />
                      <span>
                        Show all catalog results
                      </span>
                    </label>
                  </div>
                </div>
              </div>

              <div class="space-y-3">
                <UTable :data="catalogRows" :columns="columns" :loading="catalogPending" />
                <UAlert
                  v-if="catalogError"
                  color="error"
                  variant="soft"
                  icon="i-lucide-alert-triangle"
                  :description="catalogError.message"
                />
                <p v-else-if="!catalogPending && !catalogRows.length" class="text-sm text-neutral-500 dark:text-neutral-400">
                  No catalog entries match the current search term.
                </p>
              </div>
            </div>

            <div class="space-y-4">
              <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Current focus
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ trackedProductCount.toLocaleString() }}
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Products are saved locally and tied to the anonymous session shown above.
                </p>
                <div class="mt-4 space-y-2">
                  <USwitch
                    :model-value="showOwnedOnly"
                    :disabled="!trackedProducts.length"
                    aria-label="Toggle catalog focus"
                    @update:model-value="setShowOwnedOnly"
                  />
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ showOwnedOnly ? 'Catalog views will only show tracked products.' : 'Enable to limit dashboards to your tracked list.' }}
                  </p>
                </div>
              </div>

              <div class="space-y-3 rounded-lg border border-neutral-200 bg-white/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
                <div class="flex items-center justify-between">
                  <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
                    Tracked products
                  </p>
                  <UButton
                    color="neutral"
                    variant="ghost"
                    icon="i-lucide-rotate-ccw"
                    size="xs"
                    :disabled="!trackedProducts.length"
                    @click="clearTrackedProducts"
                  >
                    Clear all
                  </UButton>
                </div>
                <div v-if="trackedProducts.length" class="space-y-2">
                  <div
                    v-for="product in trackedProducts"
                    :key="product.productKey"
                    class="flex items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-sm dark:border-neutral-800 dark:bg-neutral-900/40"
                  >
                    <div class="min-w-0">
                      <p class="truncate font-semibold text-neutral-800 dark:text-neutral-100">
                        {{ product.productName }}
                      </p>
                      <p class="truncate text-xs text-neutral-500 dark:text-neutral-400">
                        {{ product.vendorName }}
                      </p>
                    </div>
                    <UButton color="neutral" size="xs" variant="soft" icon="i-lucide-x" @click="removeItem(product.productKey)">
                      Remove
                    </UButton>
                  </div>
                </div>
                <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                  Nothing tracked yet—add products from the catalog on the left.
                </p>

                <UAlert
                  v-if="saveError"
                  color="error"
                  variant="soft"
                  icon="i-lucide-alert-triangle"
                  :description="saveError"
                />
                <p v-else-if="isSaving" class="text-xs text-neutral-500 dark:text-neutral-400">
                  Saving your focus list…
                </p>
              </div>
            </div>
          </div>
        </UCard>
      </div>
    </UPageBody>
  </UPage>
</template>
