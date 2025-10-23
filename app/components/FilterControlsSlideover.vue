<script setup lang="ts">
import { computed } from "vue";
import type { ActiveFilter } from "~/types/dashboard";

const props = defineProps<{
  open: boolean;
  hasActiveFilters: boolean;
  hasActiveFilterChips: boolean;
  searchInput: string;
  selectedSource: "all" | "kev" | "enisa" | "historic" | "metasploit";
  yearRange: [number, number];
  yearSliderMin: number;
  yearSliderMax: number;
  cvssRange: [number, number];
  defaultCvssRange: readonly [number, number];
  epssRange: [number, number];
  defaultEpssRange: readonly [number, number];
  priceRange: [number, number];
  defaultPriceRange: readonly [number, number];
  priceSliderEnabled: boolean;
  activeFilters: ActiveFilter[];
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "update:search-input", value: string): void;
  (event: "update:selected-source", value: "all" | "kev" | "enisa" | "historic" | "metasploit"): void;
  (event: "update:year-range", value: [number, number]): void;
  (event: "update:cvss-range", value: [number, number]): void;
  (event: "update:epss-range", value: [number, number]): void;
  (event: "update:price-range", value: [number, number]): void;
  (event: "reset"): void;
  (event: "clear-filter", key: ActiveFilter["key"]): void;
}>();

const open = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const searchModel = computed({
  get: () => props.searchInput,
  set: (value: string) => emit("update:search-input", value),
});

const hasSearchTerm = computed(() => searchModel.value.trim().length > 0);

const selectedSource = computed({
  get: () => props.selectedSource,
  set: (value: "all" | "kev" | "enisa" | "historic" | "metasploit") => emit("update:selected-source", value),
});

const yearRange = computed({
  get: () => props.yearRange,
  set: (value: [number, number]) => emit("update:year-range", value),
});

const cvssRange = computed({
  get: () => props.cvssRange,
  set: (value: [number, number]) => emit("update:cvss-range", value),
});

const epssRange = computed({
  get: () => props.epssRange,
  set: (value: [number, number]) => emit("update:epss-range", value),
});

const priceRange = computed({
  get: () => props.priceRange,
  set: (value: [number, number]) => emit("update:price-range", value),
});

const currencyFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  maximumFractionDigits: 0,
});

const handleReset = () => {
  emit("reset");
};

const handleClearFilter = (key: ActiveFilter["key"]) => {
  emit("clear-filter", key);
};

const clearSearch = () => {
  searchModel.value = "";
};

const sourceLabels: Record<"all" | "kev" | "enisa" | "historic" | "metasploit", string> = {
  all: "All sources",
  kev: "CISA KEV",
  enisa: "ENISA",
  historic: "Historic dataset",
  metasploit: "Metasploit",
};

const selectSource = (value: "all" | "kev" | "enisa" | "historic" | "metasploit") => {
  selectedSource.value = value;
};
</script>

<template>
  <USlideover
    v-model:open="open"
    title="Filters"
    description="Refine the KEV catalog with precise search, score, and time controls."
    :ui="{ content: 'max-w-2xl' }"
    :unmount-on-hide="false"
  >
    <template #body>
      <div class="space-y-6">
        <div class="flex items-start justify-between gap-3">
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Tune the dataset without leaving the table view.
          </p>
          <UButton
            color="neutral"
            variant="ghost"
            size="sm"
            icon="i-lucide-rotate-ccw"
            :disabled="!props.hasActiveFilters"
            @click="handleReset"
          >
            Reset
          </UButton>
        </div>

        <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <UFormField label="Search">
            <UInput
              v-model="searchModel"
              class="w-full"
              placeholder="Filter by CVE, vendor, product, or description"
            >
              <template v-if="hasSearchTerm" #trailing>
                <UButton
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-x"
                  aria-label="Clear search"
                  @click.stop.prevent="clearSearch"
                />
              </template>
            </UInput>
          </UFormField>

          <UFormField label="Data source">
            <div class="flex flex-wrap gap-2">
              <UButton
                v-for="option in ['all', 'kev', 'enisa', 'historic', 'metasploit']"
                :key="option"
                size="sm"
                :color="selectedSource === option ? 'primary' : 'neutral'"
                :variant="selectedSource === option ? 'solid' : 'outline'"
                @click="selectSource(option as 'all' | 'kev' | 'enisa' | 'historic' | 'metasploit')"
              >
                {{ sourceLabels[option as 'all' | 'kev' | 'enisa' | 'historic' | 'metasploit'] }}
              </UButton>
            </div>
          </UFormField>
        </div>

        <div class="grid gap-6 grid-cols-1">
          <UFormField label="Year range">
            <div class="space-y-2">
              <USlider
                v-model="yearRange"
                :min="props.yearSliderMin"
                :max="props.yearSliderMax"
                :step="1"
                class="px-1"
                tooltip
              />
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Filter vulnerabilities by the year CISA added them to the KEV catalog.
              </p>
            </div>
          </UFormField>

          <UFormField label="CVSS range">
            <div class="space-y-2">
              <USlider
                v-model="cvssRange"
                :min="props.defaultCvssRange[0]"
                :max="props.defaultCvssRange[1]"
                :step="0.1"
                :min-steps-between-thumbs="1"
                tooltip
              />
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Common Vulnerability Scoring System (0–10) shows vendor-assigned severity.
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                {{ cvssRange[0].toFixed(1) }} – {{ cvssRange[1].toFixed(1) }}
              </p>
            </div>
          </UFormField>

          <UFormField label="EPSS range">
            <div class="space-y-2">
              <USlider
                v-model="epssRange"
                :min="props.defaultEpssRange[0]"
                :max="props.defaultEpssRange[1]"
                :step="1"
                :min-steps-between-thumbs="1"
                tooltip
              />
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Exploit Prediction Scoring System (0–100%) estimates likelihood of exploitation.
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                {{ Math.round(epssRange[0]) }} – {{ Math.round(epssRange[1]) }}
              </p>
            </div>
          </UFormField>

          <UFormField label="Reward range">
            <div class="space-y-2">
              <USlider
                v-model="priceRange"
                :min="props.defaultPriceRange[0]"
                :max="props.defaultPriceRange[1]"
                :step="1000"
                :disabled="!props.priceSliderEnabled"
                :min-steps-between-thumbs="1"
                tooltip
              />
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Filter vulnerabilities by the highest linked payout signal.
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                <span v-if="props.priceSliderEnabled">
                  {{ currencyFormatter.format(priceRange[0]) }} –
                  {{ currencyFormatter.format(priceRange[1]) }}
                </span>
                <span v-else>Reward data not available.</span>
              </p>
            </div>
          </UFormField>
        </div>

        <div class="space-y-6">
          <UFormField label="Active filters" v-if="props.hasActiveFilterChips">
            <div class="flex flex-wrap items-center gap-2">
              <UButton
                v-for="item in props.activeFilters"
                :key="`${item.key}-${item.value}`"
                size="xs"
                color="neutral"
                variant="soft"
                class="rounded-full"
                :trailing-icon="'i-lucide-x'"
                @click="handleClearFilter(item.key)"
              >
                <span class="font-medium">{{ item.label }}:</span>
                <span class="truncate max-w-[12rem]">{{ item.value }}</span>
              </UButton>
            </div>
          </UFormField>

          <UAlert
            v-else
            color="info"
            variant="soft"
            icon="i-lucide-info"
            title="No filters applied"
            description="Use the controls above to narrow the results."
          />
        </div>
      </div>
    </template>
  </USlideover>
</template>
