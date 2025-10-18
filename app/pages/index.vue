<script setup lang="ts">
import {
  computed,
  h,
  onBeforeUnmount,
  reactive,
  ref,
  resolveComponent,
  watch,
} from "vue";
import { format, parseISO } from "date-fns";
import type { SelectMenuItem, TableColumn } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import type { KevEntry } from "~/types";

const {
  entries,
  getWellKnownCveName,
  earliestDate,
  lastAddedDate,
  updatedAt,
  importLatest,
  importing,
  importError,
  lastImportSummary,
} = useKevData();

const totalEntries = computed(() => entries.value.length);

const formatTimestamp = (value: string) => {
  const parsed = parseISO(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return format(parsed, "yyyy-MM-dd HH:mm");
};

const catalogUpdatedAt = computed(() => {
  const value = updatedAt.value;
  if (!value) {
    return "No imports yet";
  }

  return formatTimestamp(value);
});

const importSummaryMessage = computed(() => {
  const summary = lastImportSummary.value;
  if (!summary) {
    return null;
  }

  const importedAt = formatTimestamp(summary.importedAt);
  const importedCount = summary.imported.toLocaleString();
  return `Imported ${importedCount} entries from the ${summary.dateReleased} release (${summary.catalogVersion}) on ${importedAt}.`;
});

const handleImport = async () => {
  await importLatest();
};

const sliderMinYear = 1990;
const sliderMaxYear = new Date().getFullYear();
const defaultYearRange = [sliderMinYear, sliderMaxYear] as const;

const yearRange = ref<[number, number]>([
  defaultYearRange[0],
  defaultYearRange[1],
]);

const hasCustomYearRange = computed(
  () =>
    yearRange.value[0] !== defaultYearRange[0] ||
    yearRange.value[1] !== defaultYearRange[1]
);

const earliestDataYear = computed(
  () => earliestDate.value?.getFullYear() ?? sliderMinYear
);

const latestDataYear = computed(
  () => lastAddedDate.value?.getFullYear() ?? sliderMaxYear
);

type FilterKey = "domain" | "exploit" | "vulnerability" | "vendor" | "product";

interface FilterState {
  domain: string | null;
  exploit: string | null;
  vulnerability: string | null;
  vendor: string | null;
  product: string | null;
}

const defaultFilters: FilterState = {
  domain: null,
  exploit: null,
  vulnerability: null,
  vendor: null,
  product: null,
};

const filters = reactive<FilterState>({ ...defaultFilters });

const searchInput = ref("");
const debouncedSearch = ref("");
const showWellKnownOnly = ref(false);

let searchDebounce: ReturnType<typeof setTimeout> | undefined;

watch(
  searchInput,
  (value) => {
    if (searchDebounce) {
      clearTimeout(searchDebounce);
    }

    searchDebounce = setTimeout(() => {
      debouncedSearch.value = value.trim();
    }, 250);
  },
  { immediate: true }
);

onBeforeUnmount(() => {
  if (searchDebounce) {
    clearTimeout(searchDebounce);
  }
});

const filterByArray = (
  items: KevEntry[],
  accessor: (entry: KevEntry) => string[],
  value: string | null
) => {
  if (!value) {
    return items;
  }

  return items.filter((entry) => accessor(entry).includes(value));
};

const filterByValue = (
  items: KevEntry[],
  accessor: (entry: KevEntry) => string,
  value: string | null
) => {
  if (!value) {
    return items;
  }

  return items.filter((entry) => accessor(entry) === value);
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

const yearFilteredEntries = computed(() => {
  const [startYear, endYear] = yearRange.value;

  return entries.value.filter((entry) => {
    const parsed = parseISO(entry.dateAdded);
    if (Number.isNaN(parsed.getTime())) {
      return true;
    }

    const year = parsed.getFullYear();
    return year >= startYear && year <= endYear;
  });
});

const textFilteredEntries = computed(() => {
  const term = debouncedSearch.value.trim().toLowerCase();

  return yearFilteredEntries.value.filter((entry) => {
    if (showWellKnownOnly.value && !getWellKnownCveName(entry.cveId)) {
      return false;
    }

    if (!term) {
      return true;
    }

    const text = `${entry.cveId} ${entry.vendor} ${entry.product} ${entry.vulnerabilityName}`.toLowerCase();
    return text.includes(term);
  });
});

const domainCounts = computed(() =>
  computeCounts(textFilteredEntries.value, (entry) => entry.domainCategories)
);

const domainFilteredEntries = computed(() =>
  filterByArray(textFilteredEntries.value, (entry) => entry.domainCategories, filters.domain)
);

const exploitCounts = computed(() =>
  computeCounts(domainFilteredEntries.value, (entry) => entry.exploitLayers)
);

const exploitFilteredEntries = computed(() =>
  filterByArray(domainFilteredEntries.value, (entry) => entry.exploitLayers, filters.exploit)
);

const vulnerabilityCounts = computed(() =>
  computeCounts(exploitFilteredEntries.value, (entry) => entry.vulnerabilityCategories)
);

const vulnerabilityFilteredEntries = computed(() =>
  filterByArray(
    exploitFilteredEntries.value,
    (entry) => entry.vulnerabilityCategories,
    filters.vulnerability
  )
);

const vendorCounts = computed(() =>
  computeCounts(vulnerabilityFilteredEntries.value, (entry) => entry.vendor)
);

const vendorFilteredEntries = computed(() =>
  filterByValue(vulnerabilityFilteredEntries.value, (entry) => entry.vendor, filters.vendor)
);

const productCounts = computed(() =>
  computeCounts(vendorFilteredEntries.value, (entry) => entry.product)
);

const productFilteredEntries = computed(() =>
  filterByValue(vendorFilteredEntries.value, (entry) => entry.product, filters.product)
);

const results = computed(() => productFilteredEntries.value);

const hasActiveFilters = computed(() =>
  Boolean(
    debouncedSearch.value.trim() ||
      filters.domain ||
      filters.exploit ||
      filters.vulnerability ||
      filters.vendor ||
      filters.product ||
      showWellKnownOnly.value ||
      hasCustomYearRange.value
  )
);

const resetYearRange = () => {
  yearRange.value = [defaultYearRange[0], defaultYearRange[1]];
};

const resetFilters = () => {
  Object.assign(filters, defaultFilters);
  if (searchDebounce) {
    clearTimeout(searchDebounce);
    searchDebounce = undefined;
  }
  searchInput.value = "";
  debouncedSearch.value = "";
  showWellKnownOnly.value = false;
  resetYearRange();
};

type ProgressDatum = {
  name: string;
  count: number;
  percent: number;
  percentLabel: string;
};

const percentFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
});

const MS_PER_DAY = 1000 * 60 * 60 * 24;

const datedResults = computed(() =>
  results.value.filter((entry) => {
    const parsed = parseISO(entry.dateAdded);
    return !Number.isNaN(parsed.getTime());
  })
);

const undatedResultsCount = computed(
  () => results.value.length - datedResults.value.length
);

type TimelineYearStat = { year: number; count: number };

type TimelineStats = {
  topYears: TimelineYearStat[];
  topYear: TimelineYearStat | null;
  yearSpan: string | null;
  activeYears: number;
  recentCount: number;
  recentShare: string | null;
  lastFiveYearsCount: number;
  lastFiveYearsShare: string | null;
  averageAgeYears: number | null;
  withDateCount: number;
};

const timelineStats = computed<TimelineStats>(() => {
  const withDate = datedResults.value;

  if (!withDate.length) {
    return {
      topYears: [],
      topYear: null,
      yearSpan: null,
      activeYears: 0,
      recentCount: 0,
      recentShare: null,
      lastFiveYearsCount: 0,
      lastFiveYearsShare: null,
      averageAgeYears: null,
      withDateCount: 0,
    };
  }

  const counts = new Map<number, number>();
  const now = new Date();
  const lastYearCutoff = new Date(now);
  lastYearCutoff.setFullYear(lastYearCutoff.getFullYear() - 1);
  const fiveYearCutoff = now.getFullYear() - 4;
  let recentCount = 0;
  let lastFiveYearsCount = 0;
  let totalDays = 0;

  for (const entry of withDate) {
    const parsed = parseISO(entry.dateAdded);
    if (Number.isNaN(parsed.getTime())) {
      continue;
    }

    const year = parsed.getFullYear();
    const nextCount = (counts.get(year) ?? 0) + 1;
    counts.set(year, nextCount);

    if (parsed >= lastYearCutoff) {
      recentCount += 1;
    }

    if (year >= fiveYearCutoff) {
      lastFiveYearsCount += 1;
    }

    totalDays += (now.getTime() - parsed.getTime()) / MS_PER_DAY;
  }

  const items = Array.from(counts.entries()).map(([year, count]) => ({
    year,
    count,
  }));

  const topYears = items
    .slice()
    .sort((a, b) => (b.count - a.count) || (b.year - a.year))
    .slice(0, 3);

  const orderedByYear = items
    .slice()
    .sort((a, b) => a.year - b.year);

  const yearSpan =
    orderedByYear.length === 0
      ? null
      : orderedByYear.length === 1
        ? `${orderedByYear[0].year}`
        : `${orderedByYear[0].year} – ${
            orderedByYear[orderedByYear.length - 1].year
          }`;

  const averageAgeYears = Number(
    (totalDays / withDate.length / 365).toFixed(1)
  );

  const toPercent = (value: number) =>
    withDate.length
      ? percentFormatter.format((value / withDate.length) * 100)
      : null;

  return {
    topYears,
    topYear: topYears[0] ?? null,
    yearSpan,
    activeYears: counts.size,
    recentCount,
    recentShare: toPercent(recentCount),
    lastFiveYearsCount,
    lastFiveYearsShare: toPercent(lastFiveYearsCount),
    averageAgeYears: Number.isFinite(averageAgeYears) ? averageAgeYears : null,
    withDateCount: withDate.length,
  };
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

const domainStats = computed(() => toProgressStats(domainCounts.value));
const exploitLayerStats = computed(() => toProgressStats(exploitCounts.value));
const vulnerabilityStats = computed(() => toProgressStats(vulnerabilityCounts.value));
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

const domainTotalCount = computed(() =>
  domainCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const exploitLayerTotalCount = computed(() =>
  exploitCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const vulnerabilityTotalCount = computed(() =>
  vulnerabilityCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const vendorTotalCount = computed(() =>
  vendorCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const productTotalCount = computed(() =>
  productCounts.value.reduce((sum, item) => sum + item.count, 0)
);

const topDomainStat = computed(() => domainStats.value[0] ?? null);
const topExploitLayerStat = computed(() => exploitLayerStats.value[0] ?? null);
const topVulnerabilityStat = computed(() => vulnerabilityStats.value[0] ?? null);

const filterLabels: Record<FilterKey, string> = {
  domain: "Domain",
  exploit: "Exploit profile",
  vulnerability: "Vulnerability category",
  vendor: "Vendor",
  product: "Product",
};

type ActiveFilter = {
  key: FilterKey | "search" | "wellKnown" | "yearRange";
  label: string;
  value: string;
};

const activeFilters = computed<ActiveFilter[]>(() => {
  const items: ActiveFilter[] = [];
  const term = debouncedSearch.value.trim();

  if (term) {
    items.push({ key: "search", label: "Search", value: term });
  }

  (Object.keys(filterLabels) as FilterKey[]).forEach((key) => {
    const value = filters[key];
    if (value) {
      items.push({ key, label: filterLabels[key], value });
    }
  });

  if (showWellKnownOnly.value) {
    items.push({ key: "wellKnown", label: "Focus", value: "Well-known CVEs" });
  }

  if (hasCustomYearRange.value) {
    items.push({
      key: "yearRange",
      label: "Year range",
      value: `${yearRange.value[0]}–${yearRange.value[1]}`,
    });
  }

  return items;
});

const resetDownstreamFilters = (key: FilterKey) => {
  if (key === "domain") {
    filters.exploit = null;
    filters.vulnerability = null;
    filters.vendor = null;
    filters.product = null;
  } else if (key === "exploit") {
    filters.vulnerability = null;
    filters.vendor = null;
    filters.product = null;
  } else if (key === "vulnerability") {
    filters.vendor = null;
    filters.product = null;
  } else if (key === "vendor") {
    filters.product = null;
  }
};

const toggleFilter = (key: FilterKey, value: string) => {
  filters[key] = filters[key] === value ? null : value;
  resetDownstreamFilters(key);
};

const clearFilter = (key: FilterKey | "search" | "wellKnown" | "yearRange") => {
  if (key === "search") {
    if (searchDebounce) {
      clearTimeout(searchDebounce);
      searchDebounce = undefined;
    }
    searchInput.value = "";
    debouncedSearch.value = "";
    return;
  }

  if (key === "wellKnown") {
    showWellKnownOnly.value = false;
    return;
  }

  if (key === "yearRange") {
    resetYearRange();
    return;
  }

  filters[key] = null;
  resetDownstreamFilters(key);
};

const columns: TableColumn<KevEntry>[] = [
  {
    id: "summary",
    header: "Description",
    cell: ({ row }) => {
      const description = row.original.description || "No description provided.";
      const wellKnownLabel = getWellKnownCveName(row.original.cveId);
      const descriptionChildren = [] as Array<ReturnType<typeof h>>;

      if (wellKnownLabel) {
        descriptionChildren.push(
          h(
            UBadge,
            {
              color: "primary",
              variant: "soft",
              class: "shrink-0 text-xs font-semibold",
            },
            () => wellKnownLabel
          )
        );
      }

      descriptionChildren.push(
        h(
          "span",
          {
            class:
              "text-sm text-neutral-500 dark:text-neutral-400 max-w-xl whitespace-normal break-words text-pretty leading-relaxed",
          },
          description
        )
      );

      return h("div", { class: "space-y-1" }, [
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
              "flex flex-wrap items-start gap-2 text-neutral-500 dark:text-neutral-400",
          },
          descriptionChildren
        ),
      ]);
    },
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
          <div
            class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <div class="space-y-2">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Data freshness
              </p>
              <p class="text-sm text-neutral-600 dark:text-neutral-300">
                Last imported release: <span class="font-medium">{{ catalogUpdatedAt }}</span>
              </p>
              <p
                v-if="totalEntries > 0"
                class="text-xs text-neutral-500 dark:text-neutral-400"
              >
                {{ totalEntries.toLocaleString() }} entries cached locally for instant filtering.
              </p>
              <p
                v-else
                class="text-xs text-neutral-500 dark:text-neutral-400"
              >
                No entries cached yet. Use the import button to fetch the latest KEV data.
              </p>
              <p
                v-if="importSummaryMessage && !importError"
                class="text-xs text-neutral-500 dark:text-neutral-400"
              >
                {{ importSummaryMessage }}
              </p>
            </div>
            <div class="flex w-full flex-col items-stretch gap-2 sm:w-auto sm:items-end">
              <UButton
                color="primary"
                icon="i-lucide-cloud-download"
                :loading="importing"
                :disabled="importing"
                @click="handleImport"
              >
                {{ importing ? "Importing…" : "Import latest KEV" }}
              </UButton>
              <UAlert
                v-if="importError"
                color="error"
                variant="soft"
                icon="i-lucide-alert-triangle"
                title="Import failed"
                :description="importError"
              />
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
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

          <div class="space-y-4">
            <UFormField label="Year range">
              <div class="space-y-3">
                <div
                  class="flex flex-wrap items-center justify-between gap-3 text-xs text-neutral-500 dark:text-neutral-400"
                >
                  <span class="font-medium text-neutral-700 dark:text-neutral-200">
                    {{ yearRange[0] }} – {{ yearRange[1] }}
                  </span>
                  <div class="flex items-center gap-2">
                    <span class="hidden text-[0.8rem] text-neutral-500 dark:text-neutral-400 sm:inline">
                      Catalog coverage {{ earliestDataYear }} – {{ latestDataYear }}
                    </span>
                    <UButton
                      v-if="hasCustomYearRange"
                      size="xs"
                      variant="ghost"
                      color="neutral"
                      icon="i-lucide-undo2"
                      @click="resetYearRange"
                    >
                      Reset
                    </UButton>
                  </div>
                </div>
                <USlider
                  v-model="yearRange"
                  :min="sliderMinYear"
                  :max="sliderMaxYear"
                  :step="1"
                  class="px-1"
                  tooltip
                />
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Filter vulnerabilities by the year CISA added them to the KEV catalog.
                </p>
              </div>
            </UFormField>

            <UFormField label="Search" class="w-full">
              <UInput
                class="w-full"
                v-model="searchInput"
                placeholder="Filter by CVE, vendor, or product"
              />
            </UFormField>

            <UFormField label="Well-known focus">
              <div class="flex items-center justify-between gap-3">
                <p class="text-sm text-neutral-600 dark:text-neutral-300">
                  Only show named, high-profile CVEs
                </p>
                <USwitch v-model="showWellKnownOnly" />
              </div>
            </UFormField>

            <div
              v-if="activeFilters.length"
              class="flex flex-wrap items-center gap-2"
            >
              <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                Active filters
              </p>
              <button
                v-for="item in activeFilters"
                :key="`${item.key}-${item.value}`"
                type="button"
                class="flex items-center gap-1 rounded-full bg-neutral-100 px-3 py-1 text-sm text-neutral-700 transition hover:bg-neutral-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 dark:bg-neutral-800 dark:text-neutral-200 dark:hover:bg-neutral-700 dark:focus-visible:ring-neutral-600"
                @click="clearFilter(item.key)"
              >
                <span>{{ item.label }}: {{ item.value }}</span>
                <UIcon name="i-lucide-x" class="size-3.5" />
              </button>
            </div>

            <div v-if="hasActiveFilters">
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
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                  Timeline insights
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Understand when the current selection entered the KEV catalog
                </p>
              </div>
              <UBadge color="neutral" variant="soft" class="shrink-0">
                {{ results.length }} in view
              </UBadge>
            </div>
          </template>

          <div class="space-y-6">
            <div class="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                  Active window
                </p>
                <p class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ timelineStats.yearSpan ?? "No dated records" }}
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  {{ timelineStats.activeYears }} documented year{{ timelineStats.activeYears === 1 ? "" : "s" }} in this view
                </p>
              </div>
              <div class="text-right">
                <UBadge color="primary" variant="soft" class="justify-end">
                  {{ timelineStats.withDateCount }} dated entries
                </UBadge>
                <p
                  v-if="undatedResultsCount"
                  class="mt-1 text-xs text-neutral-500 dark:text-neutral-400"
                >
                  {{ undatedResultsCount }} without a recorded date
                </p>
              </div>
            </div>

            <UAlert
              v-if="undatedResultsCount"
              color="warning"
              variant="soft"
              icon="i-lucide-alert-triangle"
              title="Missing timeline data"
              description="Entries without a recorded date remain visible even when you narrow the year range."
            />

            <div class="grid gap-4 md:grid-cols-3">
              <div
                class="space-y-2 rounded-xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-900/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Most active year
                </p>
                <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ timelineStats.topYear ? timelineStats.topYear.year : "—" }}
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  <template v-if="timelineStats.topYear">
                    {{ timelineStats.topYear.count }} vulnerabilities recorded
                  </template>
                  <template v-else>
                    No dated entries in range
                  </template>
                </p>
              </div>

              <div
                class="space-y-2 rounded-xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-900/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Last 12 months
                </p>
                <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ timelineStats.recentShare ? `${timelineStats.recentShare}%` : "—" }}
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  {{ timelineStats.recentCount }} vulnerabilities added in the last 12 months
                </p>
              </div>

              <div
                class="space-y-2 rounded-xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-900/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Aging profile
                </p>
                <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{
                    timelineStats.averageAgeYears !== null
                      ? `${timelineStats.averageAgeYears} yrs`
                      : "—"
                  }}
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  <template v-if="timelineStats.lastFiveYearsShare">
                    {{ timelineStats.lastFiveYearsShare }}% added in the last five years
                  </template>
                  <template v-else>
                    Not enough dated entries to calculate
                  </template>
                </p>
              </div>
            </div>

            <div v-if="timelineStats.topYears.length" class="space-y-2">
              <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
                Top activity years
              </p>
              <ul class="space-y-1">
                <li
                  v-for="item in timelineStats.topYears"
                  :key="item.year"
                  class="flex items-center justify-between rounded-lg bg-neutral-50 px-3 py-2 text-sm text-neutral-700 dark:bg-neutral-800/60 dark:text-neutral-200"
                >
                  <span class="font-semibold text-neutral-900 dark:text-neutral-50">
                    {{ item.year }}
                  </span>
                  <span class="text-neutral-500 dark:text-neutral-400">
                    {{ item.count }} KEVs
                  </span>
                </li>
              </ul>
            </div>

            <div v-else class="text-sm text-neutral-500 dark:text-neutral-400">
              No dated entries are available for the selected filters.
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-col gap-1">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Category insights
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                Compare how the filtered vulnerabilities distribute across domains and categories
              </p>
            </div>
          </template>

          <div class="grid gap-6 lg:grid-cols-3">
            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
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

              <div v-if="domainStats.length" class="space-y-3">
                <button
                  v-for="stat in domainStats"
                  :key="stat.name"
                  type="button"
                  @click="toggleFilter('domain', stat.name)"
                  :aria-pressed="filters.domain === stat.name"
                  :class="[
                    'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 dark:focus-visible:ring-emerald-600',
                    filters.domain === stat.name
                      ? 'bg-emerald-50 dark:bg-emerald-500/10 ring-emerald-200 dark:ring-emerald-500/40'
                      : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
                  ]"
                >
                  <div class="flex items-center justify-between gap-3 text-sm">
                    <span
                      :class="[
                        'truncate font-medium',
                        filters.domain === stat.name
                          ? 'text-emerald-600 dark:text-emerald-400'
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
                  <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
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

              <div v-if="exploitLayerStats.length" class="space-y-3">
                <button
                  v-for="stat in exploitLayerStats"
                  :key="stat.name"
                  type="button"
                  @click="toggleFilter('exploit', stat.name)"
                  :aria-pressed="filters.exploit === stat.name"
                  :class="[
                    'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 dark:focus-visible:ring-amber-600',
                    filters.exploit === stat.name
                      ? 'bg-amber-50 dark:bg-amber-500/10 ring-amber-200 dark:ring-amber-500/40'
                      : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
                  ]"
                >
                  <div class="flex items-center justify-between gap-3 text-sm">
                    <span
                      :class="[
                        'truncate font-medium',
                        filters.exploit === stat.name
                          ? 'text-amber-600 dark:text-amber-400'
                          : 'text-neutral-900 dark:text-neutral-50',
                      ]"
                    >
                      {{ stat.name }}
                    </span>
                    <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress :model-value="stat.percent" :max="100" color="warning" size="sm" />
                </button>
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
                  {{ topExploitLayerStat.name }} ({{ topExploitLayerStat.percentLabel }}%)
                </span>
              </div>
            </div>

            <div class="space-y-4">
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1">
                  <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
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

              <div v-if="vulnerabilityStats.length" class="space-y-3">
                <button
                  v-for="stat in vulnerabilityStats"
                  :key="stat.name"
                  type="button"
                  @click="toggleFilter('vulnerability', stat.name)"
                  :aria-pressed="filters.vulnerability === stat.name"
                  :class="[
                    'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400 dark:focus-visible:ring-rose-600',
                    filters.vulnerability === stat.name
                      ? 'bg-rose-50 dark:bg-rose-500/10 ring-rose-200 dark:ring-rose-500/40'
                      : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
                  ]"
                >
                  <div class="flex items-center justify-between gap-3 text-sm">
                    <span class="truncate font-medium text-neutral-900 dark:text-neutral-50">
                      {{ stat.name }}
                    </span>
                    <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                      {{ stat.count }} · {{ stat.percentLabel }}%
                    </span>
                  </div>
                  <UProgress :model-value="stat.percent" :max="100" color="error" size="sm" />
                </button>
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
                  {{ topVulnerabilityStat.name }} ({{ topVulnerabilityStat.percentLabel }}%)
                </span>
              </div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
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
                  <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
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

              <div v-if="topVendorStats.length" class="space-y-3">
                <button
                  v-for="stat in topVendorStats"
                  :key="stat.name"
                  type="button"
                  @click="toggleFilter('vendor', stat.name)"
                  :aria-pressed="filters.vendor === stat.name"
                  :class="[
                    'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:focus-visible:ring-primary-600',
                    filters.vendor === stat.name
                      ? 'bg-primary-50 dark:bg-primary-500/10 ring-primary-200 dark:ring-primary-500/40'
                      : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
                  ]"
                >
                  <div class="flex items-center justify-between gap-3 text-sm">
                    <span
                      :class="[
                        'truncate font-medium',
                        filters.vendor === stat.name
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
                  {{ productTotalCount }}
                </UBadge>
              </div>

              <div v-if="topProductStats.length" class="space-y-3">
                <button
                  v-for="stat in topProductStats"
                  :key="stat.name"
                  type="button"
                  @click="toggleFilter('product', stat.name)"
                  :aria-pressed="filters.product === stat.name"
                  :class="[
                    'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-secondary-400 dark:focus-visible:ring-secondary-600',
                    filters.product === stat.name
                      ? 'bg-secondary-50 dark:bg-secondary-500/10 ring-secondary-200 dark:ring-secondary-500/40'
                      : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
                  ]"
                >
                  <div class="flex items-center justify-between gap-3 text-sm">
                    <span
                      :class="[
                        'truncate font-medium',
                        filters.product === stat.name
                          ? 'text-secondary-600 dark:text-secondary-400'
                          : 'text-neutral-900 dark:text-neutral-50',
                      ]"
                    >
                      {{ stat.name }}
                    </span>
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

        <UCard>
          <template #header>
            <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
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
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
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
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Vendor
                    </p>
                    <p class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.vendor }}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Product
                    </p>
                    <p class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.product }}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Date added
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.dateAdded }}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Ransomware use
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.ransomwareUse || 'Not specified' }}
                    </p>
                  </div>
                </div>

                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Description
                  </p>
                  <div
                    class="flex flex-wrap items-start gap-2 text-sm leading-relaxed text-neutral-600 dark:text-neutral-300"
                  >
                    <UBadge
                      v-if="getWellKnownCveName(detailEntry.cveId)"
                      color="primary"
                      variant="soft"
                      class="shrink-0 text-xs font-semibold"
                    >
                      {{ getWellKnownCveName(detailEntry.cveId) }}
                    </UBadge>
                    <span class="max-w-4xl whitespace-normal break-words">
                      {{ detailEntry.description || 'No description provided.' }}
                    </span>
                  </div>
                </div>

                <div class="grid gap-3 sm:grid-cols-3">
                  <div class="space-y-2">
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
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
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
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
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
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
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Notes
                  </p>
                  <ul class="list-disc space-y-1 pl-4 text-sm text-neutral-600 dark:text-neutral-300">
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
