<script setup lang="ts">
import { computed } from 'vue'
import type { TrackedProduct } from '~/types'

const props = defineProps<{
  trackedProducts: TrackedProduct[]
  trackedProductCount: number
  hasTrackedProducts: boolean
  saving: boolean
  saveError: string | null
  manageHref?: string
}>()

const showOwnedOnly = defineModel<boolean>({ default: false })

const emits = defineEmits<{ remove: [string]; clear: []; manage: [] }>()

const manageHref = computed(() => props.manageHref ?? '/settings/software')

const headerStatus = computed(() => {
  if (props.saving) {
    return 'Saving…'
  }
  if (props.saveError) {
    return props.saveError
  }
  return props.hasTrackedProducts
    ? `${props.trackedProductCount} product${props.trackedProductCount === 1 ? '' : 's'} selected`
    : 'No products selected yet'
})
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="space-y-1">
          <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
            My software focus
          </p>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Highlight the products you care about and filter the catalog against them instantly.
          </p>
        </div>
        <div class="flex flex-col text-right leading-tight">
          <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
            {{ headerStatus }}
          </span>
          <span class="text-xs text-neutral-500 dark:text-neutral-400">
            Stored in your browser and anonymised session.
          </span>
        </div>
      </div>
    </template>

    <div class="space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <USwitch v-model="showOwnedOnly" :disabled="!props.hasTrackedProducts" aria-label="Limit catalog to tracked software" />
          <div class="flex flex-col leading-tight">
            <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
              Focus on my software
            </span>
            <span class="text-xs text-neutral-500 dark:text-neutral-400">
              {{ showOwnedOnly ? 'Catalog filtered to tracked products' : 'Toggle to restrict analytics to your list' }}
            </span>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <UButton
            color="primary"
            icon="i-lucide-sliders"
            :to="manageHref"
            variant="soft"
            @click="emits('manage')"
          >
            Manage tracked software
          </UButton>
          <UButton
            color="neutral"
            variant="ghost"
            icon="i-lucide-rotate-ccw"
            :disabled="!props.hasTrackedProducts"
            @click="emits('clear')"
          >
            Clear list
          </UButton>
        </div>
      </div>

      <div v-if="props.trackedProducts.length" class="flex flex-wrap gap-2">
        <div
          v-for="product in props.trackedProducts"
          :key="product.productKey"
          class="group inline-flex items-center gap-2 rounded-full border border-primary-200/70 bg-primary-50 px-3 py-1 text-sm dark:border-primary-500/40 dark:bg-primary-500/10"
        >
          <div class="flex flex-col leading-tight">
            <span class="font-semibold text-primary-700 dark:text-primary-300">
              {{ product.productName }}
            </span>
            <span class="text-xs text-primary-600/80 dark:text-primary-300/80">
              {{ product.vendorName }}
            </span>
          </div>
          <button
            type="button"
            class="text-xs text-primary-700 transition hover:text-primary-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:text-primary-300 dark:hover:text-primary-100"
            @click="emits('remove', product.productKey)"
          >
            Remove
          </button>
        </div>
      </div>
      <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
        You haven’t selected any products yet. Use the settings page to search the catalog and build your watch list.
      </p>

      <UAlert
        v-if="props.saveError"
        color="error"
        variant="soft"
        icon="i-lucide-alert-triangle"
        :description="props.saveError"
      />
    </div>
  </UCard>
</template>
