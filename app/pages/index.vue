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

const formatTimestamp = (value: string) => {
  const parsed = parseISO(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return format(parsed, "yyyy-MM-dd HH:mm");
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
const defaultCvssRange = [0, 10] as const;
const defaultEpssRange = [0, 100] as const;
const cvssRange = ref<[number, number]>([defaultCvssRange[0], defaultCvssRange[1]]);
const epssRange = ref<[number, number]>([defaultEpssRange[0], defaultEpssRange[1]]);
const selectedSource = ref<"all" | "kev" | "enisa">("all");

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

const filterParams = computed(() => {
  const [startYear, endYear] = yearRange.value;
  const [cvssStart, cvssEnd] = cvssRange.value;
  const [epssStart, epssEnd] = epssRange.value;

  const params: Record<string, unknown> = {
    search: debouncedSearch.value || undefined,
    domain: filters.domain || undefined,
    exploit: filters.exploit || undefined,
    vulnerability: filters.vulnerability || undefined,
    vendor: filters.vendor || undefined,
    product: filters.product || undefined,
    startYear,
    endYear,
    wellKnownOnly: showWellKnownOnly.value ? true : undefined,
  };

  if (selectedSource.value !== "all") {
    params.source = selectedSource.value;
  }

  if (cvssStart > defaultCvssRange[0] || cvssEnd < defaultCvssRange[1]) {
    params.cvssMin = cvssStart;
    params.cvssMax = cvssEnd;
  }

  if (epssStart > defaultEpssRange[0] || epssEnd < defaultEpssRange[1]) {
    params.epssMin = epssStart;
    params.epssMax = epssEnd;
  }

  return params;
});

const {
  entries,
  counts,
  catalogBounds,
  updatedAt,
  importLatest,
  importing,
  importError,
  lastImportSummary,
  importProgress,
  getWellKnownCveName,
} = useKevData(filterParams);

const totalEntries = computed(() => entries.value.length);

const earliestDataYear = computed(() => {
  const value = catalogBounds.value.earliest;
  if (!value) {
    return sliderMinYear;
  }

  const parsed = parseISO(value);
  return Number.isNaN(parsed.getTime()) ? sliderMinYear : parsed.getFullYear();
});

const latestDataYear = computed(() => {
  const value = catalogBounds.value.latest;
  if (!value) {
    return sliderMaxYear;
  }

  const parsed = parseISO(value);
  return Number.isNaN(parsed.getTime()) ? sliderMaxYear : parsed.getFullYear();
});

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
  const kevCount = summary.kevImported.toLocaleString();
  const enisaCount = summary.enisaImported.toLocaleString();
  const enisaDetail = summary.enisaImported
    ? ` Latest ENISA update: ${summary.enisaLastUpdated ? formatTimestamp(summary.enisaLastUpdated) : 'not provided'}.`
    : '';

  return `Imported ${kevCount} CISA KEV entries and ${enisaCount} ENISA entries from the ${summary.dateReleased} release (${summary.catalogVersion}) on ${importedAt}.${enisaDetail}`;
});

const importProgressPhase = computed(() => importProgress.value.phase);
const importProgressPercent = computed(() => {
  const { total, completed, phase } = importProgress.value;
  if (phase === "complete") {
    return 100;
  }
  if (total > 0) {
    return Math.min(100, Math.round((completed / total) * 100));
  }
  if (phase === "preparing") {
    return 10;
  }
  if (phase === "enriching") {
    return 80;
  }
  if (phase === "saving" || phase === "savingEnisa") {
    return total === 0 ? 90 : Math.min(100, Math.round((completed / total) * 100));
  }
  return 0;
});

const showImportProgress = computed(() => {
  const phase = importProgressPhase.value;
  if (phase === "idle") {
    return importing.value;
  }
  if (phase === "complete") {
    return false;
  }
  return true;
});

const importProgressMessage = computed(() => {
  const { message, phase, error } = importProgress.value;
  if (phase === "idle" && importing.value) {
    return "Preparing catalog import…";
  }
  if (phase === "error" && error) {
    return error;
  }
  if (message) {
    return message;
  }
  return "Importing the latest vulnerability data…";
});

const hasProgressValue = computed(() => {
  const percent = importProgressPercent.value;
  return Number.isFinite(percent) && percent > 0 && percent <= 100;
});

const handleImport = async () => {
  await importLatest();
};

const UBadge = resolveComponent("UBadge");
const UButton = resolveComponent("UButton");

const cvssSeverityColors: Record<Exclude<KevEntry["cvssSeverity"], null>, string> = {
  None: "success",
  Low: "primary",
  Medium: "warning",
  High: "error",
  Critical: "error",
};

const sourceBadgeMap: Record<KevEntry["sources"][number], { label: string; color: string }> = {
  kev: { label: "CISA KEV", color: "primary" },
  enisa: { label: "ENISA", color: "success" },
};

const formatCvssScore = (score: number | null) =>
  typeof score === "number" && Number.isFinite(score)
    ? score.toFixed(1)
    : null;

const formatEpssScore = (score: number | null) =>
  typeof score === "number" && Number.isFinite(score)
    ? score.toFixed(1)
    : null;

const formatOptionalTimestamp = (value: string | null) => {
  if (!value) {
    return "Not available";
  }

  return formatTimestamp(value);
};

const buildCvssLabel = (
  severity: KevEntry["cvssSeverity"],
  score: number | null
) => {
  const parts: string[] = [];

  if (severity) {
    parts.push(severity);
  }

  const formatted = formatCvssScore(score);
  if (formatted) {
    parts.push(formatted);
  }

  if (!parts.length) {
    parts.push("Unknown");
  }

  return parts.join(" ");
};

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

const domainCounts = computed(() => counts.value.domain);

const exploitCounts = computed(() => counts.value.exploit);

const vulnerabilityCounts = computed(() => counts.value.vulnerability);

const vendorCounts = computed(() => counts.value.vendor);

const productCounts = computed(() => counts.value.product);

const results = computed(() => {
  const term = debouncedSearch.value.trim().toLowerCase();
  if (!term) {
    return entries.value;
  }

  const includesTerm = (value: string | null | undefined) =>
    typeof value === "string" && value.toLowerCase().includes(term);

  return entries.value.filter((entry) => {
    return (
      includesTerm(entry.cveId) ||
      includesTerm(entry.vendor) ||
      includesTerm(entry.product) ||
      includesTerm(entry.vulnerabilityName) ||
      includesTerm(entry.description)
    );
  });
});

const hasActiveFilters = computed(() => {
  const hasSearch = Boolean(debouncedSearch.value.trim());
  const hasDomainFilters =
    filters.domain ||
    filters.exploit ||
    filters.vulnerability ||
    filters.vendor ||
    filters.product;
  const hasCvssFilter =
    cvssRange.value[0] > defaultCvssRange[0] || cvssRange.value[1] < defaultCvssRange[1];
  const hasEpssFilter =
    epssRange.value[0] > defaultEpssRange[0] || epssRange.value[1] < defaultEpssRange[1];
  const hasSourceFilter = selectedSource.value !== "all";

  return Boolean(
    hasSearch ||
      hasDomainFilters ||
      showWellKnownOnly.value ||
      hasCustomYearRange.value ||
      hasCvssFilter ||
      hasEpssFilter ||
      hasSourceFilter
  );
});

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
  cvssRange.value = [defaultCvssRange[0], defaultCvssRange[1]];
  epssRange.value = [defaultEpssRange[0], defaultEpssRange[1]];
  selectedSource.value = "all";
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
  key:
    | FilterKey
    | "search"
    | "wellKnown"
    | "yearRange"
    | "source"
    | "cvssRange"
    | "epssRange";
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

  if (selectedSource.value !== "all") {
    const label = selectedSource.value === "kev" ? "CISA KEV" : "ENISA";
    items.push({ key: "source", label: "Source", value: label });
  }

  if (cvssRange.value[0] > defaultCvssRange[0] || cvssRange.value[1] < defaultCvssRange[1]) {
    const [min, max] = cvssRange.value;
    items.push({
      key: "cvssRange",
      label: "CVSS",
      value: `${min.toFixed(1)} – ${max.toFixed(1)}`,
    });
  }

  if (epssRange.value[0] > defaultEpssRange[0] || epssRange.value[1] < defaultEpssRange[1]) {
    const [min, max] = epssRange.value;
    items.push({
      key: "epssRange",
      label: "EPSS",
      value: `${Math.round(min)} – ${Math.round(max)}`,
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

const setSourceFilter = (value: "all" | "kev" | "enisa") => {
  selectedSource.value = value;
};

const clearFilter = (
  key:
    | FilterKey
    | "search"
    | "wellKnown"
    | "yearRange"
    | "source"
    | "cvssRange"
    | "epssRange"
) => {
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

  if (key === "source") {
    selectedSource.value = "all";
    return;
  }

  if (key === "cvssRange") {
    cvssRange.value = [defaultCvssRange[0], defaultCvssRange[1]];
    return;
  }

  if (key === "epssRange") {
    epssRange.value = [defaultEpssRange[0], defaultEpssRange[1]];
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
      const badgeRowChildren = [] as Array<ReturnType<typeof h>>;

      for (const source of row.original.sources) {
        const meta = sourceBadgeMap[source];
        badgeRowChildren.push(
          h(
            UBadge,
            {
              color: meta?.color ?? "neutral",
              variant: "soft",
              class: "text-xs font-semibold",
            },
            () => meta?.label ?? source.toUpperCase()
          )
        );
      }

      if (wellKnownLabel) {
        badgeRowChildren.push(
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

      if (badgeRowChildren.length) {
        descriptionChildren.push(
          h(
            "div",
            { class: "flex flex-wrap items-center gap-2" },
            badgeRowChildren
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
    id: "cvss",
    header: "CVSS",
    cell: ({ row }) => {
      const { cvssScore, cvssSeverity } = row.original;
      const formattedScore = formatCvssScore(cvssScore);

      if (!formattedScore && !cvssSeverity) {
        return h(
          "span",
          { class: "text-sm text-neutral-400 dark:text-neutral-500" },
          "—"
        );
      }

      const label = buildCvssLabel(cvssSeverity, cvssScore);
      const color = cvssSeverity
        ? cvssSeverityColors[cvssSeverity] ?? "neutral"
        : "neutral";

      return h(
        UBadge,
        {
          color,
          variant: "soft",
          class: "font-semibold",
        },
        () => label
      );
    },
  },
  {
    id: "epss",
    header: "EPSS",
    cell: ({ row }) => {
      const score = formatEpssScore(row.original.epssScore);
      if (!score) {
        return h(
          "span",
          { class: "text-sm text-neutral-400 dark:text-neutral-500" },
          "—"
        );
      }

      return h(
        UBadge,
        {
          color: "success",
          variant: "soft",
          class: "font-semibold",
        },
        () => `${score}%`
      );
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


    <UPageBody>
      <div class="grid grid-cols-1 gap-3 w-full px-8 mx-auto">
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
                No entries cached yet. Use the import button to fetch the latest KEV and ENISA data.
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
                {{ importing ? "Importing…" : "Import latest data" }}
              </UButton>
              <UAlert
                v-if="importError"
                color="error"
                variant="soft"
                icon="i-lucide-alert-triangle"
                title="Import failed"
                :description="importError"
              />
              <div
                v-else-if="showImportProgress"
                class="w-full space-y-2 rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-300"
              >
                <div class="flex items-center justify-between gap-3">
                  <span class="font-medium text-neutral-700 dark:text-neutral-200">
                    Import status
                  </span>
                  <span
                    v-if="hasProgressValue"
                    class="tabular-nums text-neutral-600 dark:text-neutral-300"
                  >
                    {{ importProgressPercent }}%
                  </span>
                </div>
                <UProgress
                  v-if="hasProgressValue"
                  :value="importProgressPercent"
                  size="xs"
                  :ui="{
                    rounded: 'rounded-md',
                    track: 'bg-neutral-200 dark:bg-neutral-800',
                    indicator: 'bg-primary-500 dark:bg-primary-400'
                  }"
                />
                <p class="text-[0.78rem] text-neutral-500 dark:text-neutral-400">
                  {{ importProgressMessage }}
                </p>
              </div>
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
                placeholder="Filter by CVE, vendor, product, or description"
              />
            </UFormField>

            <UFormField label="Data source">
              <div class="flex flex-wrap gap-2">
                <UButton
                  v-for="option in ['all', 'kev', 'enisa']"
                  :key="option"
                  size="sm"
                  :color="selectedSource === option ? 'primary' : 'neutral'"
                  :variant="selectedSource === option ? 'solid' : 'outline'"
                  @click="setSourceFilter(option as 'all' | 'kev' | 'enisa')"
                >
                  {{ option === 'all' ? 'All sources' : option === 'kev' ? 'CISA KEV' : 'ENISA' }}
                </UButton>
              </div>
            </UFormField>

            <UFormField label="CVSS range">
              <div class="space-y-2">
                <USlider
                  v-model="cvssRange"
                  :min="defaultCvssRange[0]"
                  :max="defaultCvssRange[1]"
                  :step="0.1"
                  :min-steps-between-thumbs="1"
                  tooltip
                />
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  {{ cvssRange[0].toFixed(1) }} – {{ cvssRange[1].toFixed(1) }}
                </p>
              </div>
            </UFormField>

            <UFormField label="EPSS range">
              <div class="space-y-2">
                <USlider
                  v-model="epssRange"
                  :min="defaultEpssRange[0]"
                  :max="defaultEpssRange[1]"
                  :step="1"
                  :min-steps-between-thumbs="1"
                  tooltip
                />
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  {{ Math.round(epssRange[0]) }} – {{ Math.round(epssRange[1]) }}
                </p>
              </div>
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
                <div class="flex flex-wrap items-center gap-2 text-sm text-neutral-500 dark:text-neutral-400">
                  <ULink
                    :href="`https://nvd.nist.gov/vuln/detail/${detailEntry.cveId}`"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="font-medium text-primary-600 hover:underline dark:text-primary-400"
                  >
                    {{ detailEntry.cveId }}
                  </ULink>
                  <UBadge
                    v-for="source in detailEntry.sources"
                    :key="source"
                    :color="sourceBadgeMap[source]?.color ?? 'neutral'"
                    variant="soft"
                    class="text-xs font-semibold"
                  >
                    {{ sourceBadgeMap[source]?.label ?? source.toUpperCase() }}
                  </UBadge>
                </div>
              </div>
            </template>

            <template #default>
              <div class="space-y-4">
                <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
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
                  <div class="space-y-1">
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      CVSS
                    </p>
                    <div
                      v-if="detailEntry.cvssScore !== null || detailEntry.cvssSeverity"
                      class="flex items-center gap-2"
                    >
                      <UBadge
                        :color="
                          detailEntry.cvssSeverity
                            ? cvssSeverityColors[detailEntry.cvssSeverity] ?? 'neutral'
                            : 'neutral'
                        "
                        variant="soft"
                        class="font-semibold"
                      >
                        {{
                          buildCvssLabel(
                            detailEntry.cvssSeverity,
                            detailEntry.cvssScore
                          )
                        }}
                      </UBadge>
                      <span
                        v-if="detailEntry.cvssVersion"
                        class="text-xs text-neutral-500 dark:text-neutral-400"
                      >
                        v{{ detailEntry.cvssVersion }}
                      </span>
                    </div>
                    <p
                      v-else
                      class="text-base text-neutral-500 dark:text-neutral-400"
                    >
                      Not available
                    </p>
                    <p
                      v-if="detailEntry.cvssVector"
                      class="text-xs font-mono text-neutral-600 dark:text-neutral-300 break-all"
                    >
                      {{ detailEntry.cvssVector }}
                    </p>
                    <p
                      v-else
                      class="text-xs text-neutral-400 dark:text-neutral-500"
                    >
                      CVSS vector not available.
                    </p>
                  </div>
                  <div class="space-y-1">
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      EPSS
                    </p>
                    <div v-if="formatEpssScore(detailEntry.epssScore)" class="flex items-center gap-2">
                      <UBadge color="success" variant="soft" class="font-semibold">
                        {{ formatEpssScore(detailEntry.epssScore) }}%
                      </UBadge>
                    </div>
                    <p
                      v-else
                      class="text-base text-neutral-500 dark:text-neutral-400"
                    >
                      Not available
                    </p>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Assigner
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.assigner || 'Not available' }}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Exploited since
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ formatOptionalTimestamp(detailEntry.exploitedSince) }}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                      Last updated
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ formatOptionalTimestamp(detailEntry.dateUpdated) }}
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

                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Source
                  </p>
                  <div class="text-sm text-neutral-600 dark:text-neutral-300">
                    <template v-if="detailEntry.sourceUrl">
                      <ULink
                        :href="detailEntry.sourceUrl"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="font-medium text-primary-600 hover:underline dark:text-primary-400"
                      >
                        View advisory
                      </ULink>
                    </template>
                    <span v-else>Not available</span>
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

                <div v-if="detailEntry.references.length" class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    References
                  </p>
                  <ul class="list-disc space-y-1 pl-4 text-sm text-neutral-600 dark:text-neutral-300">
                    <li v-for="reference in detailEntry.references" :key="reference">
                      <ULink
                        :href="reference"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="break-all text-primary-600 hover:underline dark:text-primary-400"
                      >
                        {{ reference }}
                      </ULink>
                    </li>
                  </ul>
                </div>

                <div v-if="detailEntry.aliases.length" class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Aliases
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <UBadge
                      v-for="alias in detailEntry.aliases"
                      :key="alias"
                      color="neutral"
                      variant="soft"
                    >
                      {{ alias }}
                    </UBadge>
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
