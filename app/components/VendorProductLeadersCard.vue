<script setup lang="ts">
import { computed } from "vue";

type FilterState = {
  domain: string | null;
  exploit: string | null;
  vulnerability: string | null;
  vendor: string | null;
  product: string | null;
};

type ProgressDatum = {
  key: string;
  name: string;
  count: number;
  percent: number;
  percentLabel: string;
  vendorName?: string;
};

type SelectOption = {
  label: string;
  value: number;
  [key: string]: unknown;
};

const props = defineProps<{
  filters: FilterState;
  topVendorStats: ProgressDatum[];
  topProductStats: ProgressDatum[];
  vendorTotalCount: number;
  productTotalCount: number;
  topCount: number;
  topCountItems: SelectOption[];
}>();

const emit = defineEmits<{
  (event: "toggle-filter", key: "vendor" | "product", value: string): void;
  (event: "update:top-count", value: number): void;
}>();

const topCount = computed({
  get: () => props.topCount,
  set: (value: number) => emit("update:top-count", value),
});

const toggle = (key: "vendor" | "product", value: string) => {
  emit("toggle-filter", key, value);
};
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="space-y-1">
          <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
            Vendor &amp; product leaders
          </p>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Spot the most frequently affected suppliers in the current view
          </p>
        </div>
        <UFormField label="Show" class="w-32">
          <USelectMenu v-model="topCount" :items="props.topCountItems" value-key="value" size="sm" />
        </UFormField>
      </div>
    </template>

    <div class="grid gap-6 md:grid-cols-2">
      <div class="space-y-4">
        <div class="flex items-start justify-between gap-3">
          <div class="space-y-1">
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Top vendors
            </p>
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Ranked by number of vulnerabilities
            </p>
          </div>
          <UBadge color="primary" variant="soft">
            {{ props.vendorTotalCount }}
          </UBadge>
        </div>

        <div v-if="props.topVendorStats.length" class="space-y-3">
          <button
            v-for="stat in props.topVendorStats"
            :key="stat.key"
            type="button"
            @click="toggle('vendor', stat.key)"
            :aria-pressed="props.filters.vendor === stat.key"
            :class="[
              'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:focus-visible:ring-primary-600',
              props.filters.vendor === stat.key
                ? 'bg-primary-50 dark:bg-primary-500/10 ring-primary-200 dark:ring-primary-500/40'
                : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
            ]"
          >
            <div class="flex items-center justify-between gap-3 text-sm">
              <span
                :class="[
                  'truncate font-medium',
                  props.filters.vendor === stat.key
                    ? 'text-primary-600 dark:text-primary-400'
                    : 'text-neutral-900 dark:text-neutral-50',
                ]"
              >
                {{ stat.name }}
              </span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                {{ stat.count }} · {{ stat.percentLabel }}%
              </span>
            </div>
            <UProgress :model-value="stat.percent" :max="100" color="primary" size="sm" />
          </button>
        </div>
        <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
          No vendor data for this filter.
        </p>
      </div>

      <div class="space-y-4">
        <div class="flex items-start justify-between gap-3">
          <div class="space-y-1">
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Top products
            </p>
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Products appearing most often in the filtered results
            </p>
          </div>
          <UBadge color="secondary" variant="soft">
            {{ props.productTotalCount }}
          </UBadge>
        </div>

        <div v-if="props.topProductStats.length" class="space-y-3">
          <button
            v-for="stat in props.topProductStats"
            :key="stat.key"
            type="button"
            @click="toggle('product', stat.key)"
            :aria-pressed="props.filters.product === stat.key"
            :class="[
              'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-secondary-400 dark:focus-visible:ring-secondary-600',
              props.filters.product === stat.key
                ? 'bg-secondary-50 dark:bg-secondary-500/10 ring-secondary-200 dark:ring-secondary-500/40'
                : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
            ]"
          >
            <div class="flex items-center justify-between gap-3 text-sm">
              <div class="min-w-0">
                <p
                  :class="[
                    'truncate font-medium',
                    props.filters.product === stat.key
                      ? 'text-secondary-600 dark:text-secondary-400'
                      : 'text-neutral-900 dark:text-neutral-50',
                  ]"
                >
                  {{ stat.name }}
                </p>
                <p v-if="stat.vendorName" class="truncate text-xs text-neutral-500 dark:text-neutral-400">
                  {{ stat.vendorName }}
                </p>
              </div>
              <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                {{ stat.count }} · {{ stat.percentLabel }}%
              </span>
            </div>
            <UProgress :model-value="stat.percent" :max="100" color="secondary" size="sm" />
          </button>
        </div>
        <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
          No product data for this filter.
        </p>
      </div>
    </div>
  </UCard>
</template>
