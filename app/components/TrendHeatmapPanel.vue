<script setup lang="ts">
import { computed, ref } from "vue";
import type { KevEntrySummary } from "~/types";
import type { QuickFilterUpdate } from "~/types/dashboard";

type HeatmapGroup = "vendor" | "product";

type HeatmapItem = {
  id: string;
  label: string;
  count: number;
  description?: string;
  update: QuickFilterUpdate | null;
};

const props = defineProps<{ entries: KevEntrySummary[] }>();

const emit = defineEmits<{ (event: "quick-filter", payload: QuickFilterUpdate): void }>();

const show = defineModel<boolean>({ default: false });

const groupBy = ref<HeatmapGroup>("vendor");

const setGroup = (value: HeatmapGroup) => {
  groupBy.value = value;
};

const numberFormatter = new Intl.NumberFormat("en-US");

const groupOptions: Array<{ label: string; value: HeatmapGroup; description: string }> = [
  {
    label: "Vendors",
    value: "vendor",
    description: "Highlight which vendors appear most in the current results.",
  },
  {
    label: "Products",
    value: "product",
    description: "Spot the busiest products for the selected filters.",
  },
];

const MAX_VISIBLE_ITEMS = 60;

const groupedItems = computed<HeatmapItem[]>(() => {
  const collection = new Map<string, HeatmapItem>();
  const mode = groupBy.value;

  for (const entry of props.entries) {
    if (mode === "vendor") {
      const vendorKey = entry.vendorKey ?? "__unknown-vendor";
      const label = entry.vendor?.trim() ? entry.vendor : "Unknown vendor";
      const id = vendorKey;

      let item = collection.get(id);
      if (!item) {
        item = {
          id,
          label,
          count: 0,
          update: entry.vendorKey
            ? {
                filters: {
                  vendor: entry.vendorKey,
                  product: null,
                },
              }
            : null,
        };
        collection.set(id, item);
      }

      item.count += 1;
      continue;
    }

    const vendorKey = entry.vendorKey ?? "__unknown-vendor";
    const productLabel = entry.product?.trim() ? entry.product : "Unknown product";
    const id = entry.productKey ?? `${vendorKey}::${productLabel.toLowerCase()}`;
    const description = entry.vendor?.trim() ?? undefined;

    let item = collection.get(id);
    if (!item) {
      item = {
        id,
        label: productLabel,
        description,
        count: 0,
        update: entry.productKey
          ? {
              filters: {
                product: entry.productKey,
                vendor: entry.vendorKey ?? null,
              },
            }
          : null,
      };
      collection.set(id, item);
    }

    if (!item.description && description) {
      item.description = description;
    }

    item.count += 1;
  }

  return Array.from(collection.values()).sort((a, b) => {
    if (b.count !== a.count) {
      return b.count - a.count;
    }

    return a.label.localeCompare(b.label);
  });
});

const visibleItems = computed(() => groupedItems.value.slice(0, MAX_VISIBLE_ITEMS));
const isTruncated = computed(() => groupedItems.value.length > MAX_VISIBLE_ITEMS);
const totalGroups = computed(() => groupedItems.value.length);
const hasData = computed(() => visibleItems.value.length > 0);

const maxCount = computed(() =>
  groupedItems.value.reduce((maximum, item) => Math.max(maximum, item.count), 0),
);

const currentGroupDescription = computed(
  () => groupOptions.find((option) => option.value === groupBy.value)?.description ?? "",
);

const groupNoun = computed(() => (groupBy.value === "vendor" ? "vendor" : "product"));

const totalGroupsLabel = computed(() => {
  const count = totalGroups.value;
  const noun = groupNoun.value;
  return `${numberFormatter.format(count)} ${noun}${count === 1 ? "" : "s"}`;
});

const truncatedGroupLabel = computed(
  () =>
    `${numberFormatter.format(MAX_VISIBLE_ITEMS)} ${groupNoun.value}${
      MAX_VISIBLE_ITEMS === 1 ? "" : "s"
    }`,
);

const computeCardStyle = (count: number) => {
  const max = maxCount.value;
  if (!max) {
    return {
      "--heatmap-card-bg": "rgba(56, 189, 248, 0.18)",
      "--heatmap-card-border": "rgba(14, 165, 233, 0.35)",
      "--heatmap-card-bg-dark": "rgba(14, 165, 233, 0.26)",
      "--heatmap-card-border-dark": "rgba(56, 189, 248, 0.45)",
    } satisfies Record<string, string>;
  }

  const ratio = Math.min(1, Math.max(0, count / max));
  const lightAlpha = 0.14 + ratio * 0.46;
  const lightBorderAlpha = 0.28 + ratio * 0.45;
  const darkAlpha = 0.22 + ratio * 0.4;
  const darkBorderAlpha = 0.35 + ratio * 0.4;

  return {
    "--heatmap-card-bg": `rgba(56, 189, 248, ${lightAlpha.toFixed(3)})`,
    "--heatmap-card-border": `rgba(14, 165, 233, ${lightBorderAlpha.toFixed(3)})`,
    "--heatmap-card-bg-dark": `rgba(14, 165, 233, ${darkAlpha.toFixed(3)})`,
    "--heatmap-card-border-dark": `rgba(56, 189, 248, ${darkBorderAlpha.toFixed(3)})`,
  } satisfies Record<string, string>;
};

const handleSelect = (item: HeatmapItem) => {
  if (!item.update) {
    return;
  }

  emit("quick-filter", item.update);
};
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="space-y-1">
          <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
            Heatmap spotlight
          </p>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Surface the vendors or products that dominate the current filters.
          </p>
        </div>
        <div class="flex items-center gap-2">
          <USwitch v-model="show" aria-label="Toggle heatmap view" />
          <div class="flex flex-col text-right leading-tight">
            <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
              Show heatmap
            </span>
            <span class="text-xs text-neutral-500 dark:text-neutral-400">
              {{ show ? "Heatmap visible" : "Heatmap hidden" }}
            </span>
          </div>
        </div>
      </div>
    </template>

    <div v-if="show" class="space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2 rounded-lg border border-neutral-200 bg-neutral-50/70 p-1 dark:border-neutral-800 dark:bg-neutral-900/40">
          <button
            v-for="option in groupOptions"
            :key="option.value"
            type="button"
            class="rounded-md px-3 py-1.5 text-sm font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-500"
            :class="[
              groupBy === option.value
                ? 'bg-primary-500/10 text-primary-600 dark:bg-primary-500/25 dark:text-primary-100'
                : 'text-neutral-600 hover:text-primary-600 dark:text-neutral-300 dark:hover:text-primary-200',
            ]"
            @click="setGroup(option.value)"
          >
            {{ option.label }}
          </button>
        </div>
        <p class="text-xs text-neutral-500 dark:text-neutral-400">
          {{ totalGroupsLabel }}
        </p>
      </div>

      <p class="text-sm text-neutral-500 dark:text-neutral-400">
        {{ currentGroupDescription }}
      </p>

      <div v-if="hasData" class="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <button
          v-for="item in visibleItems"
          :key="item.id"
          type="button"
          class="heatmap-card group flex h-full flex-col justify-between rounded-lg border px-4 py-5 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-500 disabled:cursor-not-allowed disabled:opacity-60"
          :class="[
            item.update
              ? 'hover:-translate-y-0.5 hover:shadow-sm'
              : 'cursor-not-allowed',
          ]"
          :style="computeCardStyle(item.count)"
          :disabled="!item.update"
          @click="handleSelect(item)"
          @keydown.enter.prevent="handleSelect(item)"
          @keydown.space.prevent="handleSelect(item)"
        >
          <div class="space-y-2">
            <p class="text-lg font-semibold text-neutral-900 dark:text-sky-50">
              {{ item.label }}
            </p>
            <p
              v-if="item.description && groupBy === 'product'"
              class="text-sm text-neutral-600 dark:text-neutral-300"
            >
              {{ item.description }}
            </p>
          </div>
          <p class="mt-6 text-sm font-medium text-neutral-700 dark:text-sky-100">
            {{ numberFormatter.format(item.count) }} vulnerability{{ item.count === 1 ? "" : "ies" }}
          </p>
        </button>
      </div>
      <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
        Heatmap data is unavailable for the current selection.
      </p>

      <p v-if="isTruncated" class="text-xs text-neutral-500 dark:text-neutral-400">
        Showing the top {{ truncatedGroupLabel }}.
      </p>
    </div>
    <div v-else class="text-sm text-neutral-500 dark:text-neutral-400">
      Use the switch above to reveal a three-column heatmap of the busiest vendors or products.
    </div>
  </UCard>
</template>

<style scoped>
.heatmap-card {
  background-color: var(--heatmap-card-bg, rgba(56, 189, 248, 0.18));
  border-color: var(--heatmap-card-border, rgba(14, 165, 233, 0.35));
  transition: transform 0.18s ease, box-shadow 0.18s ease;
}

.dark .heatmap-card {
  background-color: var(--heatmap-card-bg-dark, rgba(14, 165, 233, 0.26));
  border-color: var(--heatmap-card-border-dark, rgba(56, 189, 248, 0.45));
}
</style>
