<script setup lang="ts">
import {
  computed,
  nextTick,
  h,
  onBeforeUnmount,
  reactive,
  ref,
  resolveComponent,
  watch,
} from "vue";
import { format, parseISO } from "date-fns";
import type { TableColumn } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import { useTrackedProducts } from "~/composables/useTrackedProducts";
import type { KevCountDatum, KevEntry, KevEntrySummary } from "~/types";
import FilteredTrendPanel from "~/components/FilteredTrendPanel.vue";
import TrackedSoftwareSummary from "~/components/TrackedSoftwareSummary.vue";

const formatTimestamp = (value: string) => {
  const parsed = parseISO(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return format(parsed, "yyyy-MM-dd HH:mm");
};

const sliderMinYear = 2021;
const sliderMaxYear = new Date().getFullYear();

const yearRange = ref<[number, number]>([sliderMinYear, sliderMaxYear]);
const defaultYearRange = ref<[number, number]>([sliderMinYear, sliderMaxYear]);

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
const showRansomwareOnly = ref(false);
const showInternetExposedOnly = ref(false);
const showTrendLines = ref(false);
const showFilterSlideover = ref(false);
const showFocusSlideover = ref(false);
const showTrendSlideover = ref(false);
const showMySoftwareSlideover = ref(false);
const showRiskDetails = ref(false);
const defaultCvssRange = [0, 10] as const;
const defaultEpssRange = [0, 100] as const;
const cvssRange = ref<[number, number]>([defaultCvssRange[0], defaultCvssRange[1]]);
const epssRange = ref<[number, number]>([defaultEpssRange[0], defaultEpssRange[1]]);
const selectedSource = ref<"all" | "kev" | "enisa">("all");
const isFiltering = ref(false);

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

const {
  trackedProducts,
  trackedProductSet,
  removeTrackedProduct,
  clearTrackedProducts,
  showOwnedOnly,
  isSaving: savingTrackedProducts,
  saveError: trackedProductError,
  isReady: trackedProductsReady,
} = useTrackedProducts();

const trackedProductKeys = computed(() =>
  trackedProducts.value.map((item) => item.productKey)
);

const trackedProductCount = computed(() => trackedProductKeys.value.length);

const hasTrackedProducts = computed(() => trackedProductCount.value > 0);

const showOwnedOnlyEffective = computed(
  () => trackedProductsReady.value && showOwnedOnly.value
);

const productMetaMap = computed(() => {
  const map = new Map<
    string,
    { productKey: string; productName: string; vendorKey: string; vendorName: string }
  >();

  productCounts.value.forEach((item) => {
    if (!item.key) {
      return;
    }

    map.set(item.key, {
      productKey: item.key,
      productName: item.name,
      vendorKey: item.vendorKey ?? "vendor-unknown",
      vendorName: item.vendorName ?? "Unknown",
    });
  });

  trackedProducts.value.forEach((tracked) => {
    if (!map.has(tracked.productKey)) {
      map.set(tracked.productKey, {
        productKey: tracked.productKey,
        productName: tracked.productName,
        vendorKey: tracked.vendorKey,
        vendorName: tracked.vendorName,
      });
    }
  });

  return map;
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
    ransomwareOnly: showRansomwareOnly.value ? true : undefined,
    ownedOnly: showOwnedOnlyEffective.value ? true : undefined,
    internetExposedOnly: showInternetExposedOnly.value ? true : undefined,
  };

  if (showOwnedOnlyEffective.value && trackedProductKeys.value.length) {
    params.products = trackedProductKeys.value.join(",");
  }

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

const normalizedSearchTerm = computed(() => debouncedSearch.value.trim().toLowerCase());

const {
  entries,
  counts,
  catalogBounds,
  updatedAt,
  getWellKnownCveName,
  pending: dataPending,
} = useKevData(filterParams);

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

const yearBounds = computed<[number, number]>(() => {
  const earliest = earliestDataYear.value;
  const latest = latestDataYear.value;
  return [Math.min(sliderMinYear, earliest), Math.max(sliderMaxYear, latest)];
});

const yearSliderMin = computed(() => yearBounds.value[0]);
const yearSliderMax = computed(() => yearBounds.value[1]);

const hasCustomYearRange = computed(
  () =>
    yearRange.value[0] !== defaultYearRange.value[0] ||
    yearRange.value[1] !== defaultYearRange.value[1]
);

watch(
  yearBounds,
  ([min, max]) => {
    const hadCustomRange = hasCustomYearRange.value;

    if (defaultYearRange.value[0] !== min || defaultYearRange.value[1] !== max) {
      defaultYearRange.value = [min, max];
    }

    if (!hadCustomRange) {
      yearRange.value = [min, max];
      return;
    }

    const [currentStart, currentEnd] = yearRange.value;
    let nextStart = Math.min(Math.max(currentStart, min), max);
    let nextEnd = Math.min(Math.max(currentEnd, min), max);

    if (nextStart > nextEnd) {
      nextStart = min;
      nextEnd = max;
    }

    if (nextStart !== currentStart || nextEnd !== currentEnd) {
      yearRange.value = [nextStart, nextEnd];
    }
  },
  { immediate: true }
);

const hasActiveFilters = computed(() => {
  const hasSearch = Boolean(normalizedSearchTerm.value);
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
  const hasTrackedFilter = showOwnedOnlyEffective.value;

  return Boolean(
    hasSearch ||
      hasDomainFilters ||
      hasTrackedFilter ||
      showWellKnownOnly.value ||
      showInternetExposedOnly.value ||
      hasCustomYearRange.value ||
      hasCvssFilter ||
      hasEpssFilter ||
      hasSourceFilter
  );
});

const catalogUpdatedAt = computed(() => {
  const value = updatedAt.value;
  if (!value) {
    return "No imports yet";
  }

  return formatTimestamp(value);
});

const UBadge = resolveComponent("UBadge");
const UButton = resolveComponent("UButton");

const cvssSeverityColors: Record<Exclude<KevEntrySummary["cvssSeverity"], null>, string> = {
  None: "success",
  Low: "primary",
  Medium: "warning",
  High: "error",
  Critical: "error",
};

const sourceBadgeMap: Record<KevEntrySummary["sources"][number], { label: string; color: string }> = {
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
  severity: KevEntrySummary["cvssSeverity"],
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
const detailLoading = ref(false);
const detailError = ref<string | null>(null);
const detailCache = new Map<string, KevEntry>();

const createDetailPlaceholder = (entry: KevEntrySummary): KevEntry => ({
  ...entry,
  requiredAction: null,
  dueDate: null,
  notes: [],
  cwes: [],
  cvssVector: null,
  cvssVersion: null,
  assigner: null,
  datePublished: null,
  dateUpdated: null,
  exploitedSince: null,
  sourceUrl: null,
  references: [],
  aliases: [],
});

const openDetails = async (entry: KevEntrySummary) => {
  detailError.value = null;

  const cached = detailCache.get(entry.id);
  if (cached) {
    detailEntry.value = cached;
    showDetails.value = true;
    return;
  }

  detailEntry.value = createDetailPlaceholder(entry);
  showDetails.value = true;
  detailLoading.value = true;

  try {
    const response = await $fetch<KevEntry>(`/api/kev/${entry.id}`);
    detailCache.set(entry.id, response);
    detailEntry.value = response;
  } catch (exception) {
    detailError.value =
      exception instanceof Error
        ? exception.message
        : "Unable to load vulnerability details.";
  } finally {
    detailLoading.value = false;
  }
};

const closeDetails = () => {
  showDetails.value = false;
};

watch(showDetails, (value) => {
  if (!value) {
    detailEntry.value = null;
    detailError.value = null;
    detailLoading.value = false;
  }
});

const domainCounts = computed(() => counts.value.domain);

const exploitCounts = computed(() => counts.value.exploit);

const vulnerabilityCounts = computed(() => counts.value.vulnerability);

const vendorCounts = computed(() => counts.value.vendor);

const productCounts = computed(() => counts.value.product);

const results = computed(() => {
  const term = normalizedSearchTerm.value;
  const trackedKeys = trackedProductSet.value;

  let collection = entries.value;

  if (showOwnedOnlyEffective.value) {
    if (!trackedKeys.size) {
      return [];
    }

    collection = collection.filter((entry) => trackedKeys.has(entry.productKey));
  }

  if (!term) {
    return collection;
  }

  const includesTerm = (value: string | null | undefined) =>
    typeof value === "string" && value.toLowerCase().includes(term);

  return collection.filter((entry) => {
    return (
      includesTerm(entry.cveId) ||
      includesTerm(entry.vendor) ||
      includesTerm(entry.product) ||
      includesTerm(entry.vulnerabilityName) ||
      includesTerm(entry.description)
    );
  });
});

watch(
  filterParams,
  () => {
    isFiltering.value = true;
  },
  { deep: true }
);

watch(
  [results, dataPending],
  () => {
    if (!dataPending.value) {
      nextTick(() => {
        isFiltering.value = false;
      });
    }
  },
  { immediate: true, flush: "post" }
);

const isBusy = computed(() => dataPending.value || isFiltering.value);

watch(showTrendSlideover, (value) => {
  if (value) {
    showTrendLines.value = true;
  }
});

const resetYearRange = () => {
  const [start, end] = defaultYearRange.value;
  yearRange.value = [start, end];
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
  showInternetExposedOnly.value = false;
  showOwnedOnly.value = false;
  cvssRange.value = [defaultCvssRange[0], defaultCvssRange[1]];
  epssRange.value = [defaultEpssRange[0], defaultEpssRange[1]];
  selectedSource.value = "all";
  resetYearRange();
};

type ProgressDatum = {
  key: string;
  name: string;
  count: number;
  percent: number;
  percentLabel: string;
  vendorKey?: string;
  vendorName?: string;
};

const percentFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
});

const formatShare = (count: number, total: number) => {
  if (!total) {
    return { count: 0, percentLabel: null as string | null };
  }

  const percent = (count / total) * 100;
  return {
    count,
    percentLabel: percentFormatter.format(percent),
  };
};

const matchingResultsCount = computed(() => results.value.length);
const matchingResultsLabel = computed(() => matchingResultsCount.value.toLocaleString());

type AggregatedMetrics = {
  ransomwareCount: number;
  cvssSum: number;
  cvssCount: number;
  severeCount: number;
  internetExposedCount: number;
  latestEntry: KevEntrySummary | null;
  latestTimestamp: number;
};

type SeverityKey = NonNullable<KevEntrySummary["cvssSeverity"]> | "Unknown";

type SeverityDistributionDatum = {
  key: SeverityKey;
  label: string;
  color: string;
  count: number;
  percent: number;
  percentLabel: string;
};

const severityDisplayMeta: Record<SeverityKey, { label: string; color: string }> = {
  Critical: { label: "Critical", color: cvssSeverityColors.Critical },
  High: { label: "High", color: cvssSeverityColors.High },
  Medium: { label: "Medium", color: cvssSeverityColors.Medium },
  Low: { label: "Low", color: cvssSeverityColors.Low },
  None: { label: "None", color: cvssSeverityColors.None },
  Unknown: { label: "Unknown", color: "neutral" },
};

type DerivedResultSnapshot = {
  aggregated: AggregatedMetrics;
  severityDistribution: SeverityDistributionDatum[];
  latestEntries: KevEntrySummary[];
};

const derivedResultSnapshot = computed<DerivedResultSnapshot>(() => {
  const metrics: AggregatedMetrics = {
    ransomwareCount: 0,
    cvssSum: 0,
    cvssCount: 0,
    severeCount: 0,
    internetExposedCount: 0,
    latestEntry: null,
    latestTimestamp: Number.NEGATIVE_INFINITY,
  };

  const severityCounts = new Map<SeverityKey, number>();
  const latestEntries: Array<{ entry: KevEntrySummary; timestamp: number }> = [];

  for (const entry of results.value) {
    const severity = entry.cvssSeverity;
    if (severity === "High" || severity === "Critical") {
      metrics.severeCount += 1;
    }

    if (typeof entry.cvssScore === "number" && Number.isFinite(entry.cvssScore)) {
      metrics.cvssSum += entry.cvssScore;
      metrics.cvssCount += 1;
    }

    if ((entry.ransomwareUse?.toLowerCase() ?? "").includes("known")) {
      metrics.ransomwareCount += 1;
    }

    if (entry.internetExposed) {
      metrics.internetExposedCount += 1;
    }

    const severityKey = (severity ?? "Unknown") as SeverityKey;
    severityCounts.set(severityKey, (severityCounts.get(severityKey) ?? 0) + 1);

    const timestamp = Date.parse(entry.dateAdded);
    if (!Number.isNaN(timestamp)) {
      latestEntries.push({ entry, timestamp });
      if (timestamp > metrics.latestTimestamp) {
        metrics.latestTimestamp = timestamp;
        metrics.latestEntry = entry;
      }
    }
  }

  latestEntries.sort((first, second) => second.timestamp - first.timestamp);

  const total = results.value.length;
  const severityDistribution: SeverityDistributionDatum[] = total
    ? [...severityCounts.entries()]
        .map(([key, count]) => {
          const meta = severityDisplayMeta[key];
          const percent = (count / total) * 100;
          return {
            key,
            label: meta.label,
            color: meta.color,
            count,
            percent,
            percentLabel: percentFormatter.format(percent),
          };
        })
        .sort((first, second) => second.percent - first.percent)
    : [];

  return {
    aggregated: metrics,
    severityDistribution,
    latestEntries: latestEntries.slice(0, 3).map((item) => item.entry),
  };
});

const aggregatedResultMetrics = computed(() => derivedResultSnapshot.value.aggregated);

const highSeverityShare = computed(() =>
  formatShare(aggregatedResultMetrics.value.severeCount, matchingResultsCount.value)
);
const highSeverityShareLabel = computed(() => {
  const label = highSeverityShare.value.percentLabel;
  return label === null ? "—" : `${label}%`;
});
const highSeverityCount = computed(() => aggregatedResultMetrics.value.severeCount);
const highSeveritySummary = computed(() => {
  if (!matchingResultsCount.value) {
    return "No entries to analyse";
  }

  if (!highSeverityCount.value) {
    return "No high-severity CVEs in scope";
  }

  return `${highSeverityCount.value.toLocaleString()} CVEs scored High or Critical`;
});

const ransomwareShare = computed(() =>
  formatShare(aggregatedResultMetrics.value.ransomwareCount, matchingResultsCount.value)
);
const ransomwareShareLabel = computed(() => {
  const label = ransomwareShare.value.percentLabel;
  return label === null ? "—" : `${label}%`;
});
const ransomwareLinkedCount = computed(() => aggregatedResultMetrics.value.ransomwareCount);
const ransomwareSummary = computed(() => {
  if (!matchingResultsCount.value) {
    return "No entries to analyse";
  }

  if (!ransomwareLinkedCount.value) {
    return "No ransomware intelligence in this view";
  }

  return `${ransomwareLinkedCount.value.toLocaleString()} CVEs tied to ransomware activity`;
});

const internetExposedShare = computed(() =>
  formatShare(aggregatedResultMetrics.value.internetExposedCount, matchingResultsCount.value)
);
const internetExposedShareLabel = computed(() => {
  const label = internetExposedShare.value.percentLabel;
  return label === null ? "—" : `${label}%`;
});
const internetExposedCount = computed(() => aggregatedResultMetrics.value.internetExposedCount);
const internetExposedSummary = computed(() => {
  if (!matchingResultsCount.value) {
    return "No entries to analyse";
  }

  if (!internetExposedCount.value) {
    return "No confirmed internet-exposed CVEs in this view";
  }

  return `${internetExposedCount.value.toLocaleString()} CVEs likely exposed to the internet`;
});

const averageCvssScore = computed(() => {
  const { cvssSum, cvssCount } = aggregatedResultMetrics.value;
  if (!cvssCount) {
    return null;
  }

  return cvssSum / cvssCount;
});
const averageCvssLabel = computed(() => {
  const value = averageCvssScore.value;
  return value === null ? "—" : value.toFixed(1);
});
const scoredResultsCount = computed(() => aggregatedResultMetrics.value.cvssCount);
const averageCvssSummary = computed(() => {
  const count = scoredResultsCount.value;
  if (!count) {
    return "No CVSS scores available";
  }

  return `${count.toLocaleString()} CVEs with CVSS data`;
});

const quickStatItems = computed(() => [
  {
    key: "count",
    icon: "i-lucide-list-checks",
    label: "In view",
    value: `${matchingResultsLabel.value} CVEs`,
  },
  {
    key: "high",
    icon: "i-lucide-activity",
    label: "High/Critical",
    value: highSeverityShareLabel.value,
  },
  {
    key: "cvss",
    icon: "i-lucide-gauge",
    label: "Avg CVSS",
    value: averageCvssLabel.value,
  },
  {
    key: "ransomware",
    icon: "i-lucide-flame",
    label: "Ransomware",
    value: ransomwareShareLabel.value,
  },
]);

const hasActiveFilterChips = computed(() => activeFilters.value.length > 0);

const severityDistribution = computed(
  () => derivedResultSnapshot.value.severityDistribution
);

const latestResultEntries = computed(() => derivedResultSnapshot.value.latestEntries);

const latestAdditionSummaries = computed(() =>
  latestResultEntries.value.map((entry) => ({
    entry,
    dateLabel: formatOptionalTimestamp(entry.dateAdded),
    vendorProduct: `${entry.vendor} · ${entry.product}`,
    wellKnown: getWellKnownCveName(entry.cveId),
    sources: entry.sources,
    internetExposed: entry.internetExposed,
  }))
);

const toProgressStats = (counts: KevCountDatum[]): ProgressDatum[] => {
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
      key: item.key,
      name: item.name,
      count: item.count,
      percent,
      percentLabel: percentFormatter.format(percent),
      vendorKey: item.vendorKey,
      vendorName: item.vendorName,
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

const resolveFilterValueLabel = (key: FilterKey, value: string) => {
  if (key === "vendor") {
    const fromCounts = vendorCounts.value.find((item) => item.key === value)?.name;
    if (fromCounts) {
      return fromCounts;
    }

    const fromProducts = productMetaMap.value.get(value)?.vendorName;
    return fromProducts ?? value;
  }

  if (key === "product") {
    const fromCounts = productCounts.value.find((item) => item.key === value)?.name;
    if (fromCounts) {
      return fromCounts;
    }

    const fromMap = productMetaMap.value.get(value)?.productName;
    return fromMap ?? value;
  }

  return value;
};

type ActiveFilter = {
  key:
    | FilterKey
    | "search"
    | "wellKnown"
    | "internet"
    | "yearRange"
    | "source"
    | "cvssRange"
    | "epssRange"
    | "owned";
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
      items.push({
        key,
        label: filterLabels[key],
        value: resolveFilterValueLabel(key, value),
      });
    }
  });

  if (showWellKnownOnly.value) {
    items.push({ key: "wellKnown", label: "Focus", value: "Well-known CVEs" });
  }

  if (showRansomwareOnly.value) {
    items.push({ key: "ransomware", label: "Focus", value: "Ransomware-linked CVEs" });
  }

  if (showInternetExposedOnly.value) {
    items.push({ key: "internet", label: "Focus", value: "Internet-exposed CVEs" });
  }

  if (showOwnedOnlyEffective.value) {
    const summary = hasTrackedProducts.value
      ? `${trackedProductCount.value} selected`
      : "No products yet";
    items.push({ key: "owned", label: "Focus", value: `My software · ${summary}` });
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
    | "internet"
    | "ransomware"
    | "owned"
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

  if (key === "internet") {
    showInternetExposedOnly.value = false;
    return;
  }

  if (key === "ransomware") {
    showRansomwareOnly.value = false;
    return;
  }

  if (key === "owned") {
    showOwnedOnly.value = false;
    return;
  }

  filters[key] = null;
  resetDownstreamFilters(key);
};

const columns: TableColumn<KevEntrySummary>[] = [
  {
    id: "summary",
    header: "Description",
    cell: ({ row }) => {
      const description = row.original.description || "No description provided.";
      const wellKnownLabel = getWellKnownCveName(row.original.cveId);
      const badgeRowChildren = [] as Array<ReturnType<typeof h>>;

      const entry = row.original;
      const isTracked =
        trackedProductsReady.value && trackedProductSet.value.has(entry.productKey);
      const hasServerSideRce = entry.exploitLayers.some((layer) =>
        layer.startsWith("RCE · Server-side")
      );
      const hasTrivialServerSide = entry.exploitLayers.includes(
        "RCE · Server-side Non-memory"
      );

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

      if (isTracked) {
        badgeRowChildren.push(
          h(
            UBadge,
            {
              color: "warning",
              variant: "soft",
              class: "shrink-0 text-xs font-semibold",
            },
            () => "My software"
          )
        );
      }

      if (hasServerSideRce) {
        badgeRowChildren.push(
          h(
            UBadge,
            {
              color: "error",
              variant: "soft",
              class: "shrink-0 text-xs font-semibold",
            },
            () =>
              hasTrivialServerSide
                ? "Server-side RCE · Non-memory"
                : "Server-side RCE"
          )
        );
      }

      const children: Array<ReturnType<typeof h>> = [
        h(
          "p",
          {
            class:
              "max-w-xs whitespace-normal break-words font-medium text-neutral-900 dark:text-neutral-100",
          },
          row.original.vulnerabilityName
        ),
      ];

      if (badgeRowChildren.length) {
        children.push(
          h(
            "div",
            { class: "flex flex-wrap items-center gap-2 text-neutral-500 dark:text-neutral-400" },
            badgeRowChildren
          )
        );
      }

      children.push(
        h(
          "p",
          {
            class:
              "text-sm text-neutral-500 dark:text-neutral-400 max-w-xl whitespace-normal break-words text-pretty leading-relaxed",
          },
          description
        )
      );

      return h("div", { class: "space-y-1" }, children);
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
          onClick: () => void openDetails(row.original),
        })
      ),
  },
];
</script>

<template>
  <UPage>


  <UPageBody>
    <div class="relative">
      <div class="fixed right-6 top-1/3 z-40 hidden xl:flex flex-col gap-3">
        <UTooltip text="Open filters" placement="left">
          <UButton
            color="neutral"
            variant="soft"
            size="lg"
            icon="i-lucide-sliders-horizontal"
            aria-label="Open filters"
            @click="showFilterSlideover = true"
          />
        </UTooltip>
        <UTooltip text="Focus controls" placement="left">
          <UButton
            color="neutral"
            variant="soft"
            size="lg"
            icon="i-lucide-crosshair"
            aria-label="Open focus controls"
            @click="showFocusSlideover = true"
          />
        </UTooltip>
        <UTooltip text="My software focus" placement="left">
          <UButton
            color="neutral"
            variant="soft"
            size="lg"
            icon="i-lucide-monitor"
            aria-label="Open my software focus"
            @click="showMySoftwareSlideover = true"
          />
        </UTooltip>
        <UTooltip text="Trend explorer" placement="left">
          <UButton
            color="neutral"
            variant="soft"
            size="lg"
            icon="i-lucide-line-chart"
            aria-label="Open trend explorer"
            @click="showTrendSlideover = true"
          />
        </UTooltip>
      </div>

      <div class="fixed bottom-5 right-4 z-40 flex items-center gap-2 xl:hidden">
        <UTooltip text="Filters" placement="top">
          <UButton
            color="primary"
            variant="solid"
            size="md"
            icon="i-lucide-sliders-horizontal"
            aria-label="Open filters"
            @click="showFilterSlideover = true"
          />
        </UTooltip>
        <UTooltip text="Focus" placement="top">
          <UButton
            color="neutral"
            variant="soft"
            size="md"
            icon="i-lucide-crosshair"
            aria-label="Open focus controls"
            @click="showFocusSlideover = true"
          />
        </UTooltip>
        <UTooltip text="My software" placement="top">
          <UButton
            color="neutral"
            variant="soft"
            size="md"
            icon="i-lucide-monitor"
            aria-label="Open my software focus"
            @click="showMySoftwareSlideover = true"
          />
        </UTooltip>
        <UTooltip text="Trend explorer" placement="top">
          <UButton
            color="neutral"
            variant="soft"
            size="md"
            icon="i-lucide-line-chart"
            aria-label="Open trend explorer"
            @click="showTrendSlideover = true"
          />
        </UTooltip>
      </div>

      <div class="mx-auto w-full max-w-6xl space-y-5 px-4 pb-12 sm:px-6 lg:px-8">
        <div
          class="pointer-events-none fixed inset-x-0 top-24 z-50 flex justify-center px-4 sm:px-6 lg:px-8"
        >
          <QuickFilterSummary
            :quick-stat-items="quickStatItems"
            :active-filters="activeFilters"
            :has-active-filters="hasActiveFilters"
            :has-active-filter-chips="hasActiveFilterChips"
            @reset="resetFilters"
            @clear-filter="clearFilter"
          />
        </div>
        <div class="h-40 sm:h-44"></div>
        <CategoryInsightsCard
          :filters="filters"
          :domain-stats="domainStats"
          :exploit-layer-stats="exploitLayerStats"
          :vulnerability-stats="vulnerabilityStats"
          :domain-total-count="domainTotalCount"
          :exploit-layer-total-count="exploitLayerTotalCount"
          :vulnerability-total-count="vulnerabilityTotalCount"
          :top-domain-stat="topDomainStat"
          :top-exploit-layer-stat="topExploitLayerStat"
          :top-vulnerability-stat="topVulnerabilityStat"
          @toggle-filter="toggleFilter"
        />

        <VendorProductLeadersCard
          v-model:top-count="topCount"
          :filters="filters"
          :top-vendor-stats="topVendorStats"
          :top-product-stats="topProductStats"
          :vendor-total-count="vendorTotalCount"
          :product-total-count="productTotalCount"
          :top-count-items="topCountItems"
          @toggle-filter="toggleFilter"
        />

        <UCard>
          <template #header>
            <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
              Results
            </p>
          </template>

          <div class="relative">
            <UTable :data="results" :columns="columns" />
            <div
              v-if="isBusy"
              class="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 rounded-lg bg-white/70 backdrop-blur dark:bg-neutral-950/70"
            >
              <UIcon name="i-lucide-loader-2" class="size-6 animate-spin text-primary-500" />
              <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
                Refreshing view…
              </p>
            </div>
          </div>
        </UCard>
      </div>

      <KevDetailModal
        v-model:open="showDetails"
        :entry="detailEntry"
        :loading="detailLoading"
        :error="detailError"
        :source-badge-map="sourceBadgeMap"
        :cvss-severity-colors="cvssSeverityColors"
        :build-cvss-label="buildCvssLabel"
        :format-epss-score="formatEpssScore"
        :format-optional-timestamp="formatOptionalTimestamp"
        :get-well-known-cve-name="getWellKnownCveName"
        @close="closeDetails"
      />
    </div>

    <USlideover
      v-model:open="showFilterSlideover"
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
              :disabled="!hasActiveFilters"
              @click="resetFilters"
            >
              Reset
            </UButton>
          </div>

          <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
            <UFormField label="Search">
              <UInput
                v-model="searchInput"
                class="w-full"
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
                  {{
                    option === 'all'
                      ? 'All sources'
                      : option === 'kev'
                        ? 'CISA KEV'
                        : 'ENISA'
                  }}
                </UButton>
              </div>
            </UFormField>
          </div>

          <div class="grid gap-6 md:grid-cols-3">
            <UFormField label="Year range">
              <div class="space-y-2">
                <USlider
                  v-model="yearRange"
                  :min="yearSliderMin"
                  :max="yearSliderMax"
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
                  :min="defaultCvssRange[0]"
                  :max="defaultCvssRange[1]"
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
                  :min="defaultEpssRange[0]"
                  :max="defaultEpssRange[1]"
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
          </div>

          <div class="space-y-6">
            <UFormField label="Active filters" v-if="hasActiveFilterChips">
              <div class="flex flex-wrap items-center gap-2">
                <button
                  v-for="item in activeFilters"
                  :key="`${item.key}-${item.value}`"
                  type="button"
                  class="flex items-center gap-1 rounded-full bg-neutral-100 px-3 py-1 text-sm text-neutral-700 transition hover:bg-neutral-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 dark:bg-neutral-800 dark:text-neutral-200 dark:hover:bg-neutral-700 dark:focus-visible:ring-primary-500"
                  @click="clearFilter(item.key)"
                >
                  <span>{{ item.label }}: {{ item.value }}</span>
                  <UIcon name="i-lucide-x" class="size-3.5" />
                </button>
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

    <USlideover
      v-model:open="showFocusSlideover"
      title="Focus controls"
      description="Highlight the vulnerabilities that matter most to your organisation."
      :ui="{ content: 'max-w-lg' }"
      :unmount-on-hide="false"
    >
      <template #body>
        <div class="relative space-y-5">
          <div
            v-if="!trackedProductsReady"
            class="pointer-events-none absolute inset-0 rounded-xl bg-neutral-200/70 backdrop-blur-sm dark:bg-neutral-800/60"
          />

          <div class="space-y-3">
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">My software</p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Only show CVEs that match the products you track.
                </p>
              </div>
              <USwitch v-model="showOwnedOnly" :disabled="!trackedProductsReady" />
            </div>
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Named CVEs</p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Elevate high-profile, widely reported vulnerabilities.
                </p>
              </div>
              <USwitch v-model="showWellKnownOnly" />
            </div>
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Ransomware focus</p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Restrict the view to CVEs linked to ransomware campaigns.
                </p>
              </div>
              <USwitch v-model="showRansomwareOnly" />
            </div>
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Internet exposure</p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Prioritise vulnerabilities likely to be exposed on the open internet.
                </p>
              </div>
              <USwitch v-model="showInternetExposedOnly" />
            </div>
          </div>

          <div class="rounded-lg border border-neutral-200 bg-neutral-50/70 p-4 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/40 dark:text-neutral-300">
            <p class="font-semibold text-neutral-700 dark:text-neutral-100">Tracked products</p>
            <p class="mt-1">{{ trackedProductCount.toLocaleString() }} product(s) selected.</p>
            <p class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
              Manage the list on the dashboard at any time; changes are saved automatically.
            </p>
          </div>
        </div>
      </template>
    </USlideover>

    <USlideover
      v-model:open="showMySoftwareSlideover"
      title="My software focus"
      description="Adjust tracked products and the owned-only view without leaving the table."
      :ui="{ content: 'max-w-3xl' }"
      :unmount-on-hide="false"
    >
      <template #body>
        <div class="relative">
          <div
            v-if="!trackedProductsReady"
            class="pointer-events-none absolute inset-0 rounded-xl bg-neutral-200/70 backdrop-blur-sm dark:bg-neutral-800/60"
          />
          <TrackedSoftwareSummary
            v-model="showOwnedOnly"
            :tracked-products="trackedProducts"
            :tracked-product-count="trackedProductCount"
            :has-tracked-products="hasTrackedProducts"
            :saving="savingTrackedProducts"
            :save-error="trackedProductError"
            @remove="removeTrackedProduct"
            @clear="clearTrackedProducts"
          />
        </div>
      </template>
    </USlideover>

    <USlideover
      v-model:open="showTrendSlideover"
      title="Trend explorer"
      description="Visualise how the filtered vulnerabilities accumulate over time."
      :ui="{ content: 'max-w-4xl' }"
      :unmount-on-hide="false"
    >
      <template #body>
        <div class="relative space-y-6">
          <div
            v-if="isBusy"
            class="pointer-events-none absolute inset-0 z-10 rounded-xl bg-neutral-200/70 backdrop-blur-sm dark:bg-neutral-800/60"
          />

          <RiskSnapshotCard
            v-model:show-risk-details="showRiskDetails"
            :matching-results-label="matchingResultsLabel"
            :high-severity-share-label="highSeverityShareLabel"
            :high-severity-summary="highSeveritySummary"
            :average-cvss-label="averageCvssLabel"
            :average-cvss-summary="averageCvssSummary"
            :ransomware-share-label="ransomwareShareLabel"
            :ransomware-summary="ransomwareSummary"
            :internet-exposed-share-label="internetExposedShareLabel"
            :internet-exposed-summary="internetExposedSummary"
            :severity-distribution="severityDistribution"
            :latest-addition-summaries="latestAdditionSummaries"
            :source-badge-map="sourceBadgeMap"
            @open-details="openDetails"
          />

          <FilteredTrendPanel v-model="showTrendLines" :entries="results" />

          <UCard>
            <div class="space-y-1">
              <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
                Last catalog import
              </p>
              <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
                {{ catalogUpdatedAt }}
              </p>
            </div>
          </UCard>
        </div>
      </template>
    </USlideover>
  </UPageBody>
  </UPage>
</template>
