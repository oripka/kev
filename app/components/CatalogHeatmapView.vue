<script setup lang="ts">
import { computed, ref } from "vue";
import type { KevHeatmapGroups } from "~/types";
import type { QuickFilterUpdate } from "~/types/dashboard";

type HeatmapGroup = "vendor" | "product";

type HeatmapItem = {
  id: string;
  label: string;
  count: number;
  description?: string;
  update: QuickFilterUpdate | null;
};

const props = defineProps<{ heatmap: KevHeatmapGroups }>();

const emit = defineEmits<{ (event: "quick-filter", payload: QuickFilterUpdate): void }>();

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
  const mode = groupBy.value;
  const source = mode === "vendor" ? props.heatmap.vendor : props.heatmap.product;

  const items = source
    .filter((item) => item.count > 0)
    .map((item) => {
      if (mode === "vendor") {
        const key = item.key?.trim();
        const label = item.name?.trim() ? item.name : "Unknown vendor";

        return {
          id: key ?? `vendor::${label.toLowerCase()}`,
          label,
          count: item.count,
          update: key
            ? {
                filters: {
                  vendor: key,
                  product: null,
                },
              }
            : null,
        } satisfies HeatmapItem;
      }

      const productKey = item.key?.trim();
      const productLabel = item.name?.trim() ? item.name : "Unknown product";
      const vendorKey = item.vendorKey?.trim() ?? null;
      const vendorName = item.vendorName?.trim();

      return {
        id: productKey ?? `${vendorKey ?? "unknown"}::${productLabel.toLowerCase()}`,
        label: productLabel,
        description: vendorName && vendorName.length ? vendorName : undefined,
        count: item.count,
        update: productKey
          ? {
              filters: {
                product: productKey,
                vendor: vendorKey,
              },
            }
          : null,
      } satisfies HeatmapItem;
    });

  items.sort((a, b) => {
    if (b.count !== a.count) {
      return b.count - a.count;
    }

    return a.label.localeCompare(b.label);
  });

  return items;
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

const primaryInsight = computed(() => {
  const [top] = visibleItems.value;
  if (!top) {
    return null;
  }

  const noun = groupBy.value === "vendor" ? "Top vendor" : "Top product";
  const countLabel = `${numberFormatter.format(top.count)} vulnerability${top.count === 1 ? "" : "ies"}`;
  if (groupBy.value === "vendor") {
    return `${noun}: ${top.label} · ${countLabel}`;
  }

  const vendorHint = top.description ? ` · ${top.description}` : "";
  return `${noun}: ${top.label}${vendorHint} · ${countLabel}`;
});

const handleSelect = (item: HeatmapItem) => {
  if (!item.update) {
    return;
  }

  emit("quick-filter", item.update);
};
</script>

<template>
  <div class="space-y-4">
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
      <div class="flex flex-col text-right leading-tight text-xs text-neutral-500 dark:text-neutral-400">
        <span>{{ totalGroupsLabel }}</span>
        <span>{{ currentGroupDescription }}</span>
      </div>
    </div>

    <p v-if="primaryInsight" class="text-sm font-medium text-sky-700 dark:text-sky-200">
      {{ primaryInsight }}
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
          {{ numberFormatter.format(item.count) }} vulnerability{{ item.count === 1 ? '' : 'ies' }}
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
