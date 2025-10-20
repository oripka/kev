<script setup lang="ts">
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
}>();

const emit = defineEmits<{
  (event: "reset"): void;
  (event: "clear-filter", key: ActiveFilterItem["key"]): void;
}>();

const handleReset = () => {
  emit("reset");
};

const handleClear = (key: ActiveFilterItem["key"]) => {
  emit("clear-filter", key);
};
</script>

<template>
  <div
    class="pointer-events-auto flex w-full max-w-5xl flex-wrap items-center gap-3 rounded-full border border-neutral-200 bg-white/90 px-5 py-3 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-white/70 dark:border-neutral-800 dark:bg-neutral-900/90"
  >
    <div class="flex flex-1 flex-wrap items-center gap-3">
      <div class="flex flex-wrap gap-4 text-sm">
        <template v-if="props.quickStatItems.length">
          <div v-for="item in props.quickStatItems" :key="item.key" class="flex items-center gap-2">
            <UIcon :name="item.icon" class="size-4 text-primary-500 dark:text-primary-400" />
            <span class="text-neutral-500 dark:text-neutral-400">{{ item.label }}</span>
            <span class="font-semibold text-neutral-900 dark:text-neutral-50">{{ item.value }}</span>
          </div>
        </template>
        <span v-else class="text-xs text-neutral-500 dark:text-neutral-400">No summary metrics configured</span>
      </div>

      <template v-if="props.showFilterChips">
        <div class="hidden h-6 w-px bg-neutral-200 dark:bg-neutral-800 lg:block" />

        <div class="flex flex-wrap items-center gap-2">
          <template v-if="props.hasActiveFilterChips">
            <button
              v-for="item in props.activeFilters"
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
