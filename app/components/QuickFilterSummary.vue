<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { ActiveFilter, QuickFilterSummaryMetricKey } from "~/types/dashboard";

type QuickStatItem = {
  key: QuickFilterSummaryMetricKey;
  icon: string;
  label: string;
  value: string;
};

type ActiveFilterItem = Pick<ActiveFilter, "key" | "label" | "value">;

const props = defineProps<{
  quickStatItems: QuickStatItem[];
  activeFilters: ActiveFilterItem[];
  hasActiveFilters: boolean;
  hasActiveFilterChips: boolean;
  showFilterChips: boolean;
  showResetButton: boolean;
  yearRange: [number, number];
  yearBounds: readonly [number, number];
  hasCustomYearRange: boolean;
  isYearRangeLimited: boolean;
  searchInput: string;
  searchPlaceholder?: string;
}>();

const emit = defineEmits<{
  (event: "reset"): void;
  (event: "clear-filter", key: ActiveFilterItem["key"]): void;
  (event: "update:year-range", value: [number, number]): void;
  (event: "reset-year-range"): void;
  (event: "clear-year-range"): void;
  (event: "update:search-input", value: string): void;
}>();

const yearSliderValue = ref<[number, number]>([
  props.yearRange[0],
  props.yearRange[1],
]);

watch(
  () => props.yearRange,
  (value) => {
    if (
      yearSliderValue.value[0] !== value[0] ||
      yearSliderValue.value[1] !== value[1]
    ) {
      yearSliderValue.value = [value[0], value[1]];
    }
  },
  { immediate: true },
);

const yearStat = computed(() =>
  props.quickStatItems.find((item) => item.key === "year"),
);

const staticStats = computed(() =>
  props.quickStatItems.filter((item) => item.key !== "year"),
);

const filterChips = computed(() =>
  props.activeFilters.filter((item) => item.key !== "yearRange"),
);

const hasFilterChips = computed(() => filterChips.value.length > 0);

const searchModel = computed({
  get: () => props.searchInput,
  set: (value: string) => {
    emit("update:search-input", value);
  },
});

const hasSearchTerm = computed(() => searchModel.value.trim().length > 0);

const searchLabel = computed(() => {
  if (!hasSearchTerm.value) {
    return "Add search";
  }
  const term = searchModel.value.trim();
  return term.length > 24 ? `“${term.slice(0, 24)}…”` : `“${term}”`;
});

const handleReset = () => {
  emit("reset");
};

const handleClear = (key: ActiveFilterItem["key"]) => {
  emit("clear-filter", key);
};

const handleYearRangeUpdate = (value: [number, number]) => {
  yearSliderValue.value = [value[0], value[1]];
  emit("update:year-range", [value[0], value[1]]);
};

const handleResetYearRange = () => {
  emit("reset-year-range");
};

const handleClearYearRange = () => {
  emit("clear-year-range");
};

const handleClearSearch = () => {
  emit("update:search-input", "");
};
</script>

<template>
  <div
    class="pointer-events-auto flex w-full max-w-5xl flex-wrap items-center gap-3 rounded-3xl border border-neutral-200 bg-white/95 px-4 py-3 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-white/75 dark:border-neutral-800 dark:bg-neutral-900/95"
  >
    <div class="flex flex-1 flex-wrap items-center gap-3">
      <div class="flex flex-wrap items-center gap-2 text-sm">
        <template v-if="yearStat">
          <UPopover>
            <button
              type="button"
              class="group flex items-center gap-2 rounded-full border border-transparent bg-primary-50/70 px-3 py-1.5 text-xs font-medium text-primary-700 transition hover:border-primary-200 hover:bg-primary-100/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:bg-primary-500/10 dark:text-primary-200 dark:hover:border-primary-500/40"
            >
              <UIcon :name="yearStat.icon" class="size-4" />
              <span>{{ yearStat.label }}</span>
              <span class="font-semibold">{{ yearStat.value }}</span>
              <span
                role="button"
                tabindex="0"
                class="inline-flex size-5 items-center justify-center rounded-full text-primary-500 transition hover:bg-primary-100/60 hover:text-primary-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:text-primary-300 dark:hover:bg-primary-500/20 dark:hover:text-primary-200"
                aria-label="Show all years"
                @click.stop="handleClearYearRange"
                @keydown.enter.prevent.stop="handleClearYearRange"
                @keydown.space.prevent.stop="handleClearYearRange"
              >
                <UIcon name="i-lucide-x" class="size-3.5" />
              </span>
            </button>

            <template #content>
              <div class="w-72 space-y-4 p-4">
                <div class="flex items-center justify-between gap-3">
                  <div>
                    <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                      Adjust year range
                    </p>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">
                      Drag to explore additional catalog years.
                    </p>
                  </div>
                  <div class="flex gap-2">
                    <UButton
                      size="xs"
                      variant="ghost"
                      color="neutral"
                      :disabled="!props.hasCustomYearRange"
                      @click="handleResetYearRange"
                    >
                      Default
                    </UButton>
                    <UButton
                      size="xs"
                      color="primary"
                      variant="soft"
                      :disabled="!props.isYearRangeLimited"
                      @click="handleClearYearRange"
                    >
                      All years
                    </UButton>
                  </div>
                </div>
                <USlider
                  :model-value="yearSliderValue"
                  :min="props.yearBounds[0]"
                  :max="props.yearBounds[1]"
                  :step="1"
                  class="px-1"
                  tooltip
                  @update:model-value="handleYearRangeUpdate"
                />
                <div class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
                  <span>{{ yearSliderValue[0] }}</span>
                  <span>{{ yearSliderValue[1] }}</span>
                </div>
              </div>
            </template>
          </UPopover>
        </template>

        <template v-if="staticStats.length">
          <div
            v-for="item in staticStats"
            :key="item.key"
            class="flex items-center gap-2 rounded-full bg-neutral-100 px-3 py-1 text-xs text-neutral-600 dark:bg-neutral-800 dark:text-neutral-200"
          >
            <UIcon :name="item.icon" class="size-4" />
            <span>{{ item.label }}</span>
            <span class="font-semibold text-neutral-900 dark:text-neutral-50">{{ item.value }}</span>
          </div>
        </template>

        <span
          v-if="!yearStat && !staticStats.length"
          class="text-xs text-neutral-500 dark:text-neutral-400"
        >
          No summary metrics configured
        </span>
      </div>

      <UPopover>
        <button
          type="button"
          class="flex items-center gap-2 rounded-full border border-neutral-200 bg-white px-3 py-1.5 text-xs font-medium text-neutral-600 transition hover:border-primary-200 hover:text-primary-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:border-primary-500/40 dark:hover:text-primary-200"
        >
          <UIcon name="i-lucide-search" class="size-4" />
          <span>Search</span>
          <span
            class="truncate text-neutral-800 dark:text-neutral-100"
          >{{ searchLabel }}</span>
          <span
            v-if="hasSearchTerm"
            role="button"
            tabindex="0"
            class="inline-flex size-5 items-center justify-center rounded-full text-neutral-400 transition hover:bg-neutral-100 hover:text-neutral-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:text-neutral-500 dark:hover:bg-neutral-800 dark:hover:text-neutral-200"
            aria-label="Clear search"
            @click.stop="handleClearSearch"
            @keydown.enter.prevent.stop="handleClearSearch"
            @keydown.space.prevent.stop="handleClearSearch"
          >
            <UIcon name="i-lucide-x" class="size-3.5" />
          </span>
        </button>

        <template #content>
          <div class="w-72 space-y-3 p-4">
            <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              Quick search
            </p>
            <UInput
              v-model="searchModel"
              :placeholder="props.searchPlaceholder ?? 'Filter by CVE, vendor, or product'"
              autofocus
              size="sm"
              class="w-full"
            />
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
              Matches apply instantly to the catalog.
            </p>
          </div>
        </template>
      </UPopover>

      <template v-if="props.showFilterChips">
        <div class="hidden h-6 w-px bg-neutral-200 dark:bg-neutral-800 lg:block" />

        <div class="flex flex-wrap items-center gap-2">
          <template v-if="hasFilterChips">
            <button
              v-for="item in filterChips"
              :key="`${item.key}-${item.value}`"
              type="button"
              class="flex items-center gap-1 rounded-full bg-neutral-100 px-3 py-1 text-xs text-neutral-700 transition hover:bg-neutral-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:bg-neutral-800 dark:text-neutral-200 dark:hover:bg-neutral-700 dark:focus-visible:ring-primary-500"
              @click="handleClear(item.key)"
            >
              <span>{{ item.label }}: {{ item.value }}</span>
              <UIcon name="i-lucide-x" class="size-3.5" />
            </button>
          </template>
          <span v-else class="text-xs text-neutral-500 dark:text-neutral-400">No active filters</span>
        </div>
      </template>
    </div>

    <UButton
      v-if="props.showResetButton && props.hasActiveFilters"
      size="xs"
      color="neutral"
      variant="ghost"
      icon="i-lucide-rotate-ccw"
      class="ml-auto"
      @click="handleReset"
    >
      Clear
    </UButton>
  </div>
</template>
