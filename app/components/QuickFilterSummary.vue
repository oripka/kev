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
  props.activeFilters.filter(
    (item) => item.key !== "yearRange" && item.key !== "search",
  ),
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
  <UCard
    variant="subtle"
    :ui="{
      root: 'pointer-events-auto w-full rounded-3xl border border-neutral-200/80 bg-white/80 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-white/75 dark:border-neutral-800 dark:bg-neutral-900/85',
      body: 'flex flex-wrap items-center gap-3 px-4 py-3'
    }"
  >
    <div class="flex flex-1 flex-wrap items-center gap-3">
      <div class="flex flex-wrap items-center gap-2 text-sm">
        <template v-if="yearStat">
          <div class="flex items-center gap-1">
            <UPopover>
              <UButton
                size="xs"
                color="primary"
                variant="soft"
                class="rounded-full"
              >
                <template #leading>
                  <UIcon :name="yearStat.icon" class="size-4" />
                </template>
                <span class="flex items-center gap-1.5 text-xs">
                  <span>{{ yearStat.label }}</span>
                  <span class="font-semibold">{{ yearStat.value }}</span>
                </span>
                <template v-if="props.isYearRangeLimited" #trailing>
                  <span
                    class="ml-1 inline-flex h-5 w-5 cursor-pointer items-center justify-center rounded-full text-primary-600 transition hover:bg-primary-500/10 dark:text-primary-200"
                    title="Show all years"
                    @click.stop.prevent="handleClearYearRange"
                  >
                    <UIcon name="i-lucide-x" class="size-4" />
                  </span>
                </template>
              </UButton>

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
          </div>
        </template>

        <template v-if="staticStats.length">
          <UBadge
            v-for="item in staticStats"
            :key="item.key"
            color="neutral"
            variant="soft"
            size="sm"
            class="inline-flex items-center gap-2 rounded-full px-3 py-1"
          >
            <UIcon :name="item.icon" class="size-4" />
            <span>{{ item.label }}</span>
            <span class="font-semibold text-neutral-900 dark:text-neutral-50">{{ item.value }}</span>
          </UBadge>
        </template>

        <span
          v-if="!yearStat && !staticStats.length"
          class="text-xs text-neutral-500 dark:text-neutral-400"
        >
          No summary metrics configured
        </span>
      </div>

      <UPopover>
        <UButton
          size="xs"
          color="neutral"
          variant="outline"
          class="rounded-full"
        >
          <template #leading>
            <UIcon name="i-lucide-search" class="size-4" />
          </template>
          <span class="flex min-w-0 items-center gap-1 text-xs">
            <span>Search</span>
            <span class="truncate text-neutral-800 dark:text-neutral-100">
              {{ searchLabel }}
            </span>
          </span>
        </UButton>

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
            >
              <template v-if="hasSearchTerm" #trailing>
                <UButton
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-x"
                  aria-label="Clear search"
                  @click.stop.prevent="handleClearSearch"
                />
              </template>
            </UInput>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
              Matches apply instantly to the catalog.
            </p>
          </div>
        </template>
      </UPopover>

      <template v-if="props.showFilterChips">
        <USeparator
          orientation="vertical"
          class="hidden h-6 self-stretch bg-neutral-200 dark:bg-neutral-800 lg:block"
        />

        <div class="flex flex-wrap items-center gap-2">
          <template v-if="hasFilterChips">
            <UButton
              v-for="item in filterChips"
              :key="`${item.key}-${item.value}`"
              size="xs"
              color="neutral"
              variant="soft"
              class="rounded-full"
              :trailing-icon="'i-lucide-x'"
              @click="handleClear(item.key)"
            >
              <span class="font-medium">{{ item.label }}:</span>
              <span class="truncate max-w-[10rem]">{{ item.value }}</span>
            </UButton>
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
  </UCard>
</template>
