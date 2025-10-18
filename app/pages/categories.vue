<script setup lang="ts">
import { computed, h, reactive, ref, resolveComponent, watch } from "vue";
import { format, parseISO } from "date-fns";
import type { SelectMenuItem, TableColumn } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import type { KevEntry } from "~/types";

const {
  entries,
  categoryNames,
  exploitLayerNames,
  vulnerabilityTypeNames,
} = useKevData();

const defaultFilters = {
  domain: null as string | null,
  exploit: null as string | null,
  vulnerability: null as string | null,
  text: "",
};

const filters = reactive({ ...defaultFilters });

const resetFilters = () => {
  Object.assign(filters, defaultFilters);
};

const toSelectItems = (
  counts: { name: string; count: number }[],
  names: string[],
  allLabel: string,
  includeZero = true
): SelectMenuItem<string | null>[] => {
  const formatted = counts.map(({ name, count }) => ({
    label: `${name} (${count})`,
    value: name,
  }));

  const seen = new Set(counts.map((item) => item.name));
  const zeroItems = includeZero
    ? names
        .filter((name) => !seen.has(name))
        .map((name) => ({ label: `${name} (0)`, value: name }))
        .sort((a, b) => a.label.localeCompare(b.label))
    : [];

  return [{ label: allLabel, value: null }, ...formatted, ...zeroItems];
};

const computeCounts = (
  items: KevEntry[],
  accessor: (entry: KevEntry) => string | string[]
) => {
  const totals = new Map<string, number>();

  for (const entry of items) {
    const value = accessor(entry);
    const keys = Array.isArray(value) ? value : [value];

    for (const key of keys) {
      if (!key || key === "Other") {
        continue;
      }

      totals.set(key, (totals.get(key) ?? 0) + 1);
    }
  }

  return Array.from(totals.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
};

const UBadge = resolveComponent("UBadge");
const UButton = resolveComponent("UButton");

const showDetails = ref(false);
const detailEntry = ref<KevEntry | null>(null);

const openDetails = (entry: KevEntry) => {
  detailEntry.value = entry;
  showDetails.value = true;
};

const closeDetails = () => {
  showDetails.value = false;
};

watch(showDetails, (value) => {
  if (!value) {
    detailEntry.value = null;
  }
});

const results = computed(() => {
  const term = filters.text.trim().toLowerCase();
  const domain = filters.domain;
  const exploit = filters.exploit;
  const vulnerability = filters.vulnerability;

  return entries.value.filter((entry) => {
    if (
      domain &&
      !entry.domainCategories.includes(
        domain as (typeof entry.domainCategories)[number]
      )
    ) {
      return false;
    }

    if (
      exploit &&
      !entry.exploitLayers.includes(
        exploit as (typeof entry.exploitLayers)[number]
      )
    ) {
      return false;
    }

    if (
      vulnerability &&
      !entry.vulnerabilityCategories.includes(
        vulnerability as (typeof entry.vulnerabilityCategories)[number]
      )
    ) {
      return false;
    }

    if (term) {
      const text =
        `${entry.cveId} ${entry.vendor} ${entry.product} ${entry.vulnerabilityName}`.toLowerCase();
      if (!text.includes(term)) {
        return false;
      }
    }

    return true;
  });
});

const hasActiveFilters = computed(() =>
  Boolean(
    filters.domain ||
      filters.exploit ||
      filters.vulnerability ||
      filters.text.trim()
  )
);

const domainCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.domainCategories)
);

const domainCountsAll = computed(() =>
  computeCounts(entries.value, (entry) => entry.domainCategories)
);

const domainItems = computed(() =>
  toSelectItems(domainCounts.value, categoryNames.value, "All domain categories")
);

const exploitLayerCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.exploitLayers)
);

const exploitLayerCountsAll = computed(() =>
  computeCounts(entries.value, (entry) => entry.exploitLayers)
);

const exploitLayerItems = computed(() =>
  toSelectItems(
    exploitLayerCounts.value,
    exploitLayerNames.value,
    "All exploit profiles",
    !filters.domain
  )
);

const vulnerabilityCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.vulnerabilityCategories)
);

const vulnerabilityCountsAll = computed(() =>
  computeCounts(entries.value, (entry) => entry.vulnerabilityCategories)
);

const vulnerabilityItems = computed(() =>
  toSelectItems(
    vulnerabilityCounts.value,
    vulnerabilityTypeNames.value,
    "All vulnerability categories",
    !(filters.domain || filters.exploit)
  )
);

type ProgressDatum = {
  name: string;
  count: number;
  percent: number;
  percentLabel: string;
};

const percentFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
});

const toProgressStats = (
  counts: { name: string; count: number }[]
): ProgressDatum[] => {
  if (!counts.length) {
    return [];
  }

  const total = counts.reduce((sum, item) => sum + item.count, 0);
  if (!total) {
    return [];
  }

  return counts.map((item) => {
    const percent = (item.count / total) * 100;
    return {
      ...item,
      percent,
      percentLabel: percentFormatter.format(percent),
    };
  });
};

const domainStats = computed(() => toProgressStats(domainCountsAll.value));
const exploitLayerStats = computed(() =>
  toProgressStats(exploitLayerCountsAll.value)
);
const vulnerabilityStats = computed(() =>
  toProgressStats(vulnerabilityCountsAll.value)
);

const vendorCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.vendor)
);

const productCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.product)
);

const vendorStats = computed(() => toProgressStats(vendorCounts.value));
const productStats = computed(() => toProgressStats(productCounts.value));

const topCountOptions = [5, 10, 15, 20];
const topCountItems: SelectMenuItem<number>[] = topCountOptions.map((value) => ({
  label: `Top ${value}`,
  value,
}));

const topCount = ref<number>(5);

const topVendorStats = computed(() => vendorStats.value.slice(0, topCount.value));
const topProductStats = computed(() => productStats.value.slice(0, topCount.value));

const vendorTotalCount = computed(() =>
  vendorCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const productTotalCount = computed(() =>
  productCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const domainProgressColor = (name: string) =>
  filters.domain && name === filters.domain ? "secondary" : "primary";

const exploitLayerProgressColor = (name: string) =>
  filters.exploit && name === filters.exploit ? "error" : "warning";

const domainTotalCount = computed(() =>
  domainCountsAll.value.reduce((sum, item) => sum + item.count, 0)
);

const exploitLayerTotalCount = computed(() =>
  exploitLayerCountsAll.value.reduce((sum, item) => sum + item.count, 0)
);

const vulnerabilityTotalCount = computed(() =>
  vulnerabilityCountsAll.value.reduce((sum, item) => sum + item.count, 0)
);

const topDomainStat = computed(() => domainStats.value[0] ?? null);
const topExploitLayerStat = computed(() => exploitLayerStats.value[0] ?? null);
const topVulnerabilityStat = computed(() => vulnerabilityStats.value[0] ?? null);

const columns: TableColumn<KevEntry>[] = [
  {
    id: "summary",
    header: "Description",
    cell: ({ row }) =>
      h("div", { class: "space-y-1" }, [
        h(
          "p",
          {
            class:
              "max-w-xs whitespace-normal break-words font-medium text-neutral-900 dark:text-neutral-100",
          },
          row.original.vulnerabilityName
        ),
        h(
          "p",
          {
            class:
              "text-sm text-neutral-500 dark:text-neutral-400 max-w-xl whitespace-normal break-words text-pretty",
          },
          row.original.description || "No description provided."
        ),
      ]),
  },
  {
    accessorKey: "dateAdded",
    header: "Date added",
    cell: ({ row }) => {
      const parsed = parseISO(row.original.dateAdded);
      return Number.isNaN(parsed.getTime())
        ? row.original.dateAdded
        : format(parsed, "yyyy-MM-dd");
    },
  },
  {
    id: "domain",
    header: "Domain",
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex flex-wrap gap-2" },
        row.original.domainCategories.map((category) =>
          h(UBadge, { color: "primary", variant: "soft" }, () => category)
        )
      ),
  },
  {
    id: "exploit",
    header: "Exploit profile",
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex flex-wrap gap-2" },
        row.original.exploitLayers.map((layer) =>
          h(UBadge, { color: "warning", variant: "soft" }, () => layer)
        )
      ),
  },
  {
    id: "type",
    header: "Type",
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex flex-wrap gap-2" },
        row.original.vulnerabilityCategories.map((category) =>
          h(UBadge, { color: "secondary", variant: "soft" }, () => category)
        )
      ),
  },
  {
    id: "actions",
    header: "",
    enableSorting: false,
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex justify-end" },
        h(UButton, {
          icon: "i-lucide-eye",
          color: "neutral",
          variant: "ghost",
          "aria-label": `View ${row.original.cveId} details`,
          onClick: () => openDetails(row.original),
        })
      ),
  },
];
</script>

<template>
  <UPage>
    <UPageHeader
      title="Category explorer"
      description="Combine domain, exploit, and vulnerability categories to focus on what matters"
    />

    <UPageBody>
      <div class="grid grid-cols-1 gap-3 max-w-7xl mx-auto">
        <UCard>
          <template #header>
            <div class="flex items-center justify-between gap-3">
              <p
                class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
              >
                Filters
              </p>
              <UButton
                color="neutral"
                variant="ghost"
                size="sm"
                icon="i-lucide-rotate-ccw"
                @click="resetFilters"
                :disabled="!hasActiveFilters"
              >
                Reset filters
              </UButton>
            </div>
          </template>

          <div class="grid gap-2 md:grid-cols-2">
            <UFormField class="w-full" label="Domain category">
              <USelectMenu
                class="w-full"
                v-model="filters.domain"
                :items="domainItems"
                value-key="value"
                clearable
                searchable
              />
            </UFormField>

            <UFormField class="w-full" label="Exploit profile">
              <USelectMenu
                class="w-full"
                v-model="filters.exploit"
                :items="exploitLayerItems"
                value-key="value"
                clearable
                searchable
              />
            </UFormField>

            <UFormField class="w-full" label="Vulnerability category">
              <USelectMenu
                class="w-full"
                v-model="filters.vulnerability"
                :items="vulnerabilityItems"
                value-key="value"
                clearable
                searchable
              />
            </UFormField>

            <UFormField label="Search" class="w-full md:col-span-2">
              <UInput
                class="w-full"
                v-model="filters.text"
                placeholder="Filter by CVE, vendor, or product"
              />
            </UFormField>

            <div v-if="hasActiveFilters" class="md:col-span-2">
              <UAlert
                color="info"
                variant="soft"
                icon="i-lucide-filters"
                :title="`${results.length} matching vulnerabilities`"
              />
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-col gap-1">
              <p
                class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
              >
                Category insights
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                Compare how the filtered vulnerabilities distribute across
                domains and categories
              </p>
            </div>
          </template>

          <div class="grid gap-6 lg:grid-cols-3">
            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p
                    class="text-base font-semibold text-neutral-900 dark:text-neutral-50"
                  >
                    Domain coverage
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    Share of vulnerabilities per domain grouping
                  </p>
                </div>
                <UBadge color="primary" variant="soft">
                  {{ domainTotalCount }}
                </UBadge>
              </div>

              <div v-if="domainStats.length" class="space-y-4">
                <div
                  v-for="stat in domainStats"
                  :key="stat.name"
                  :class="[
                    'space-y-2 rounded-lg px-3 py-2 transition-colors ring-1 ring-transparent dark:ring-transparent',
                    filters.domain === stat.name
                      ? 'bg-emerald-50 dark:bg-emerald-500/10 ring-emerald-200 dark:ring-emerald-500/40'
                      : 'bg-transparent'
                  ]"
                >
                  <div
                    class="flex items-center justify-between gap-3 text-sm"
                  >
                    <span
                      :class="[
                        'font-medium truncate',
                        filters.domain === stat.name
                          ? 'text-emerald-600 dark:text-emerald-400'
                          : 'text-neutral-900 dark:text-neutral-50',
                      ]"
                    >
                      {{ stat.name }}
                    </span>
                    <span
                      class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap"
                    >
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress
                    :model-value="stat.percent"
                    :max="100"
                    :color="domainProgressColor(stat.name)"
                    size="sm"
                  />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No domain category data for this filter.
              </p>

              <div
                v-if="topDomainStat"
                class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400"
              >
                <span>Top domain</span>
                <span class="font-medium text-neutral-900 dark:text-neutral-50">
                  {{ topDomainStat.name }} ({{ topDomainStat.percentLabel }}%)
                </span>
              </div>
            </div>

            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p
                    class="text-base font-semibold text-neutral-900 dark:text-neutral-50"
                  >
                    Exploit dynamics
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    How execution paths cluster for these CVEs
                  </p>
                </div>
                <UBadge color="warning" variant="soft">
                  {{ exploitLayerTotalCount }}
                </UBadge>
              </div>

              <div v-if="exploitLayerStats.length" class="space-y-4">
                <div
                  v-for="stat in exploitLayerStats"
                  :key="stat.name"
                  :class="[
                    'space-y-2 rounded-lg px-3 py-2 transition-colors ring-1 ring-transparent dark:ring-transparent',
                    filters.exploit === stat.name
                      ? 'bg-amber-50 dark:bg-amber-500/10 ring-amber-200 dark:ring-amber-500/40'
                      : 'bg-transparent'
                  ]"
                >
                  <div
                    class="flex items-center justify-between gap-3 text-sm"
                  >
                    <span
                      :class="[
                        'font-medium truncate',
                        filters.exploit === stat.name
                          ? 'text-amber-600 dark:text-amber-400'
                          : 'text-neutral-900 dark:text-neutral-50',
                      ]"
                    >
                      {{ stat.name }}
                    </span>
                    <span
                      class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap"
                    >
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress
                    :model-value="stat.percent"
                    :max="100"
                    :color="exploitLayerProgressColor(stat.name)"
                    size="sm"
                  />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No exploit profile data for this filter.
              </p>

              <div
                v-if="topExploitLayerStat"
                class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400"
              >
                <span>Top profile</span>
                <span class="font-medium text-neutral-900 dark:text-neutral-50">
                  {{ topExploitLayerStat.name }}
                  ({{ topExploitLayerStat.percentLabel }}%)
                </span>
              </div>
            </div>

            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p
                    class="text-base font-semibold text-neutral-900 dark:text-neutral-50"
                  >
                    Vulnerability mix
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    Breakdown of vulnerability categories in view
                  </p>
                </div>
                <UBadge color="violet" variant="soft">
                  {{ vulnerabilityTotalCount }}
                </UBadge>
              </div>

              <div v-if="vulnerabilityStats.length" class="space-y-4">
                <div
                  v-for="stat in vulnerabilityStats"
                  :key="stat.name"
                  :class="[
                    'space-y-2 rounded-lg px-3 py-2 transition-colors ring-1 ring-transparent dark:ring-transparent',
                    filters.vulnerability === stat.name
                      ? 'bg-rose-50 dark:bg-rose-500/10 ring-rose-200 dark:ring-rose-500/40'
                      : 'bg-transparent'
                  ]"
                >
                  <div
                    class="flex items-center justify-between gap-3 text-sm"
                  >
                    <span
                      class="font-medium text-neutral-900 dark:text-neutral-50 truncate"
                    >
                      {{ stat.name }}
                    </span>
                    <span
                      class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap"
                    >
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress
                    :model-value="stat.percent"
                    :max="100"
                    color="error"
                    size="sm"
                  />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No vulnerability category data for this filter.
              </p>

              <div
                v-if="topVulnerabilityStat"
                class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400"
              >
                <span>Top category</span>
                <span class="font-medium text-neutral-900 dark:text-neutral-50">
                  {{ topVulnerabilityStat.name }}
                  ({{ topVulnerabilityStat.percentLabel }}%)
                </span>
              </div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p
                  class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
                >
                  Vendor & product leaders
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Spot the most frequently affected suppliers in the current view
                </p>
              </div>
              <UFormField label="Show" class="w-32">
                <USelectMenu
                  v-model="topCount"
                  :items="topCountItems"
                  value-key="value"
                  size="sm"
                />
              </UFormField>
            </div>
          </template>

          <div class="grid gap-6 md:grid-cols-2">
            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p
                    class="text-base font-semibold text-neutral-900 dark:text-neutral-50"
                  >
                    Top vendors
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    Ranked by number of vulnerabilities
                  </p>
                </div>
                <UBadge color="primary" variant="soft">
                  {{ vendorTotalCount }}
                </UBadge>
              </div>

              <div v-if="topVendorStats.length" class="space-y-4">
                <div
                  v-for="stat in topVendorStats"
                  :key="stat.name"
                  class="space-y-2 rounded-lg px-3 py-2 transition-colors bg-transparent ring-1 ring-transparent dark:ring-transparent"
                >
                  <div
                    class="flex items-center justify-between gap-3 text-sm"
                  >
                    <span class="font-medium truncate text-neutral-900 dark:text-neutral-50">
                      {{ stat.name }}
                    </span>
                    <span
                      class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap"
                    >
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress
                    :model-value="stat.percent"
                    :max="100"
                    color="primary"
                    size="sm"
                  />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No vendor data for this filter.
              </p>
            </div>

            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p
                    class="text-base font-semibold text-neutral-900 dark:text-neutral-50"
                  >
                    Top products
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400">
                    Products appearing most often in the filtered results
                  </p>
                </div>
                <UBadge color="secondary" variant="soft">
                  {{ productTotalCount }}
                </UBadge>
              </div>

              <div v-if="topProductStats.length" class="space-y-4">
                <div
                  v-for="stat in topProductStats"
                  :key="stat.name"
                  class="space-y-2 rounded-lg px-3 py-2 transition-colors bg-transparent ring-1 ring-transparent dark:ring-transparent"
                >
                  <div
                    class="flex items-center justify-between gap-3 text-sm"
                  >
                    <span class="font-medium truncate text-neutral-900 dark:text-neutral-50">
                      {{ stat.name }}
                    </span>
                    <span
                      class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap"
                    >
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress
                    :model-value="stat.percent"
                    :max="100"
                    color="secondary"
                    size="sm"
                  />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                No product data for this filter.
              </p>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <p
              class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
            >
              Results
            </p>
          </template>

          <UTable :data="results" :columns="columns" />
        </UCard>
      </div>

      <UModal
        v-model:open="showDetails"
        :ui="{
          content: 'w-full max-w-7xl rounded-xl shadow-lg',
          body: 'p-6 text-base text-muted',
        }"
      >
        <template #body>
          <UCard v-if="detailEntry">
            <template #header>
              <div class="space-y-1">
                <p
                  class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
                >
                  {{ detailEntry.vulnerabilityName }}
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  {{ detailEntry.cveId }}
                </p>
              </div>
            </template>

            <template #default>
              <div class="space-y-4">
                <div class="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Vendor
                    </p>
                    <p
                      class="text-base font-semibold text-neutral-900 dark:text-neutral-100"
                    >
                      {{ detailEntry.vendor }}
                    </p>
                  </div>
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Product
                    </p>
                    <p
                      class="text-base font-semibold text-neutral-900 dark:text-neutral-100"
                    >
                      {{ detailEntry.product }}
                    </p>
                  </div>
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Date added
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.dateAdded }}
                    </p>
                  </div>
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Ransomware use
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.ransomwareUse || "Not specified" }}
                    </p>
                  </div>
                </div>

                <div class="space-y-2">
                  <p
                    class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                  >
                    Description
                  </p>
                  <p
                    class="text-sm leading-relaxed text-neutral-600 dark:text-neutral-300"
                  >
                    {{ detailEntry.description || "No description provided." }}
                  </p>
                </div>

                <div class="grid gap-3 sm:grid-cols-3">
                  <div class="space-y-2">
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Domain categories
                    </p>
                    <div class="flex flex-wrap gap-2">
                      <UBadge
                        v-for="category in detailEntry.domainCategories"
                        :key="category"
                        color="primary"
                        variant="soft"
                      >
                        {{ category }}
                      </UBadge>
                    </div>
                  </div>
                  <div class="space-y-2">
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Exploit profiles
                    </p>
                    <div class="flex flex-wrap gap-2">
                      <UBadge
                        v-for="layer in detailEntry.exploitLayers"
                        :key="layer"
                        color="warning"
                        variant="soft"
                      >
                        {{ layer }}
                      </UBadge>
                    </div>
                  </div>
                  <div class="space-y-2">
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Vulnerability categories
                    </p>
                    <div class="flex flex-wrap gap-2">
                      <UBadge
                        v-for="category in detailEntry.vulnerabilityCategories"
                        :key="category"
                        color="secondary"
                        variant="soft"
                      >
                        {{ category }}
                      </UBadge>
                    </div>
                  </div>
                </div>

                <div v-if="detailEntry.notes.length" class="space-y-2">
                  <p
                    class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                  >
                    Notes
                  </p>
                  <ul
                    class="list-disc space-y-1 pl-4 text-sm text-neutral-600 dark:text-neutral-300"
                  >
                    <li v-for="note in detailEntry.notes" :key="note">
                      {{ note }}
                    </li>
                  </ul>
                </div>
              </div>
            </template>

            <template #footer>
              <div class="flex justify-end gap-2">
                <UButton color="neutral" variant="soft" @click="closeDetails">
                  Close
                </UButton>
              </div>
            </template>
          </UCard>
        </template>
      </UModal>
    </UPageBody>
  </UPage>
</template>
