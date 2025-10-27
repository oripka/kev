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
import { getPaginationRowModel } from "@tanstack/vue-table";
import { parseISO } from "date-fns";
import type { AccordionItem, SelectMenuItem, TableColumn, TableRow } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import { useTrackedProducts } from "~/composables/useTrackedProducts";
import { useCatalogPreferences } from "~/composables/useCatalogPreferences";
import { useDateDisplay } from "~/composables/useDateDisplay";
import { useMarketMetrics } from "~/composables/useMarketMetrics";
import { createFilterPresets } from "~/utils/filterPresets";
import { defaultQuickFilterSummaryConfig, quickFilterSummaryMetricInfo } from "~/utils/quickFilterSummaryConfig";
import {
  catalogSourceBadgeMap as sourceBadgeMap,
  catalogSourceLabels,
} from "~/constants/catalogSources";
import type {
  CatalogSource,
  KevCountDatum,
  KevDomainCategory,
  KevEntryDetail,
  KevEntrySummary,
  KevExploitLayer,
  KevVulnerabilityCategory,
  MarketOverview,
  MarketProgramType,
  TrackedProductQuickFilterTarget,
} from "~/types";
import type {
  ActiveFilter,
  FilterKey,
  FilterState,
  LatestAdditionSortKey,
  LatestAdditionSortOption,
  LatestAdditionSummary,
  SeverityDistributionDatum,
  SeverityKey,
  SourceBadgeMap,
  StatTrend,
  QuickFilterSummaryConfig,
  QuickFilterSummaryMetricKey,
  QuickFilterPreset,
  QuickFilterUpdate,
} from "~/types/dashboard";

const {
  formatDate,
  formatRelativeDate,
  preferences: displayPreferences,
} = useDateDisplay();

const formatTimestamp = (value: string) =>
  formatDate(value, { fallback: value, preserveInputOnError: true });

const formatMarketProgramTypeLabel = (type: MarketProgramType) => {
  if (type === "exploit-broker") {
    return "Exploit brokers";
  }
  if (type === "bug-bounty") {
    return "Bug bounty";
  }
  return "Other programs";
};

const sliderMinYear = 2021;
const sliderMaxYear = new Date().getFullYear();
const defaultYearStart = Math.max(sliderMinYear, sliderMaxYear - 1);
const defaultYearEnd = sliderMaxYear;

const defaultYearRange = ref<[number, number]>([
  defaultYearStart,
  defaultYearEnd,
]);
const yearRange = ref<[number, number]>([defaultYearStart, defaultYearEnd]);

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
const showPublicExploitOnly = ref(false);
const showTrendLines = ref(false);
const showHeatmap = ref(false);
const showCompactTable = ref(false);
const showFilterPanel = ref(true);
const showTrendSlideover = ref(false);
const showRiskDetails = ref(false);
const showAllResults = ref(false);
const showMySoftwareSlideover = ref(false);
const showClassificationReviewSlideover = ref(false);

type CatalogTableApi = {
  getState(): { pagination: { pageIndex: number; pageSize: number } };
  setPageIndex(index: number): void;
  getFilteredRowModel(): { rows: Array<unknown> };
  getPageCount(): number;
};

type CatalogTableExpose = {
  tableApi?: CatalogTableApi;
};

const table = useTemplateRef<CatalogTableExpose | null>("table");

const pagination = ref({
  pageIndex: 0,
  pageSize: 10,
});

const showRelativeDates = computed({
  get: () => displayPreferences.value.relativeDates,
  set: (value: boolean) => {
    displayPreferences.value.relativeDates = value;
  },
});

const latestAdditionWindowDays = 14;
const latestAdditionWindowMs = latestAdditionWindowDays * 24 * 60 * 60 * 1000;
const latestAdditionLimit = 5;

const latestAdditionSortKey = ref<LatestAdditionSortKey>("recent");
const latestAdditionSortOptions: LatestAdditionSortOption[] = [
  { label: "Recent", value: "recent", icon: "i-lucide-clock" },
  { label: "EPSS", value: "epss", icon: "i-lucide-activity" },
  { label: "CVSS", value: "cvss", icon: "i-lucide-gauge" },
];

const catalogPreferences = useCatalogPreferences();

const { data: quickFilterSummaryConfigData } = await useFetch<QuickFilterSummaryConfig>(
  "/api/quick-filter-summary",
  {
    default: () => defaultQuickFilterSummaryConfig,
    headers: {
      "cache-control": "no-store",
    },
  },
);

const replaceFiltersOnQuickApply = computed(
  () => catalogPreferences.value.replaceFiltersOnQuickApply
);

type SortOption = "publicationDate" | "cvssScore" | "epssScore" | "cveId";
type SortDirection = "asc" | "desc";

const sortOption = ref<SortOption>("publicationDate");
const sortDirection = ref<SortDirection>("desc");

const sortOptionItems: SelectMenuItem<SortOption>[] = [
  { label: "Publication date", value: "publicationDate" },
  { label: "EPSS score", value: "epssScore" },
  { label: "CVSS score", value: "cvssScore" },
  { label: "CVE number", value: "cveId" },
];

const sortDirectionItems: SelectMenuItem<SortDirection>[] = [
  { label: "Descending", value: "desc" },
  { label: "Ascending", value: "asc" },
];

const filterPanelToggleLabel = computed(() =>
  showFilterPanel.value ? "Expand table" : "Show filters",
);

const filterPanelToggleIcon = computed(() =>
  showFilterPanel.value ? "i-lucide-sidebar-close" : "i-lucide-sidebar-open",
);

const filterPanelToggleAriaLabel = computed(() =>
  showFilterPanel.value
    ? "Hide filters and expand table view"
    : "Show filters panel",
);

const sortBadgeLabelMap: Record<SortOption, string> = {
  publicationDate: "Published",
  epssScore: "EPSS",
  cvssScore: "CVSS",
  cveId: "CVE",
};

const sortDirectionSymbolMap: Record<SortDirection, string> = {
  asc: "↑",
  desc: "↓",
};

const sortBadgeText = computed(
  () => `${sortDirectionSymbolMap[sortDirection.value]} ${sortBadgeLabelMap[sortOption.value]}`
);
const defaultCvssRange = [0, 10] as const;
const defaultEpssRange = [0, 100] as const;
const maxEntryLimit = 25;
const cvssRange = ref<[number, number]>([
  defaultCvssRange[0],
  defaultCvssRange[1],
]);
const epssRange = ref<[number, number]>([
  defaultEpssRange[0],
  defaultEpssRange[1],
]);

const priceRange = ref<[number, number]>([0, 0]);
let priceRangeInitialised = false;
let pendingPriceRange: [number, number] | null = null;

const marketPriceBounds = ref<MarketOverview["priceBounds"]>({
  minRewardUsd: null,
  maxRewardUsd: null,
});

const defaultPriceRange = ref<[number, number]>([0, 0]);

const priceSliderReady = computed(() => {
  const bounds = marketPriceBounds.value;

  return (
    typeof bounds.minRewardUsd === "number" &&
    typeof bounds.maxRewardUsd === "number" &&
    Number.isFinite(bounds.minRewardUsd) &&
    Number.isFinite(bounds.maxRewardUsd) &&
    bounds.maxRewardUsd > bounds.minRewardUsd
  );
});

const selectedSource = ref<
  "all" | "kev" | "enisa" | "historic" | "metasploit" | "poc"
>("all");
const selectedMarketProgramType = ref<MarketProgramType | null>(null);
const isFiltering = ref(false);

const selectSource = (
  value: "all" | "kev" | "enisa" | "historic" | "metasploit" | "poc",
) => {
  selectedSource.value = value;
};

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

const route = useRoute();
const router = useRouter();

type RouteQuery = Record<string, unknown>;

const extractQueryString = (value: unknown): string | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return extractQueryString(value[value.length - 1]);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return null;
};

const parseQueryBoolean = (value: unknown): boolean | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return parseQueryBoolean(value[value.length - 1]);
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value === 1;
  }

  if (typeof value === "string") {
    const normalised = value.trim().toLowerCase();
    if (!normalised) {
      return null;
    }

    if (normalised === "true" || normalised === "1") {
      return true;
    }

    if (normalised === "false" || normalised === "0") {
      return false;
    }
  }

  return null;
};

const parseQueryInteger = (value: unknown): number | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return parseQueryInteger(value[value.length - 1]);
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    const parsed = Number.parseInt(trimmed, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }

  return null;
};

const parseQueryFloat = (value: unknown): number | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return parseQueryFloat(value[value.length - 1]);
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    const parsed = Number.parseFloat(trimmed);
    return Number.isNaN(parsed) ? null : parsed;
  }

  return null;
};

const normaliseNumericRange = (
  minimum: number | null,
  maximum: number | null,
  defaults: readonly [number, number],
  clamp: (value: number) => number,
): [number, number] => {
  let start =
    typeof minimum === "number" && Number.isFinite(minimum)
      ? minimum
      : defaults[0];
  let end =
    typeof maximum === "number" && Number.isFinite(maximum)
      ? maximum
      : defaults[1];

  start = clamp(start);
  end = clamp(end);

  if (start > end) {
    [start, end] = [end, start];
  }

  return [start, end];
};

const applyRouteQueryState = (rawQuery: RouteQuery) => {
  const getValue = (key: string) => rawQuery[key];

  const searchValue = extractQueryString(getValue("search")) ?? "";
  if (searchInput.value !== searchValue || debouncedSearch.value !== searchValue) {
    if (searchDebounce) {
      clearTimeout(searchDebounce);
      searchDebounce = undefined;
    }

    searchInput.value = searchValue;
    debouncedSearch.value = searchValue;
  }

  (Object.entries(filters) as Array<[FilterKey, string | null]>).forEach(
    ([key, currentValue]) => {
      const nextValue = extractQueryString(getValue(key));
      const normalised = nextValue ?? null;

      if (currentValue !== normalised) {
        filters[key] = normalised;
      }
    },
  );

  const startYear = parseQueryInteger(getValue("startYear"));
  const endYear = parseQueryInteger(getValue("endYear"));
  const [defaultStartYear, defaultEndYear] = defaultYearRange.value;
  const nextYearRange =
    startYear === null && endYear === null
      ? [defaultStartYear, defaultEndYear]
      : normaliseNumericRange(
          startYear,
          endYear,
          [defaultStartYear, defaultEndYear],
          (value) => Math.min(Math.max(value, sliderMinYear), sliderMaxYear),
        );

  if (
    yearRange.value[0] !== nextYearRange[0] ||
    yearRange.value[1] !== nextYearRange[1]
  ) {
    yearRange.value = nextYearRange;
  }

  const cvssMin = parseQueryFloat(getValue("cvssMin"));
  const cvssMax = parseQueryFloat(getValue("cvssMax"));
  const nextCvssRange =
    cvssMin === null && cvssMax === null
      ? [defaultCvssRange[0], defaultCvssRange[1]]
      : normaliseNumericRange(
          cvssMin,
          cvssMax,
          defaultCvssRange,
          (value) =>
            Math.min(Math.max(value, defaultCvssRange[0]), defaultCvssRange[1]),
        );

  if (
    cvssRange.value[0] !== nextCvssRange[0] ||
    cvssRange.value[1] !== nextCvssRange[1]
  ) {
    cvssRange.value = nextCvssRange;
  }

  const epssMin = parseQueryFloat(getValue("epssMin"));
  const epssMax = parseQueryFloat(getValue("epssMax"));
  const nextEpssRange =
    epssMin === null && epssMax === null
      ? [defaultEpssRange[0], defaultEpssRange[1]]
      : normaliseNumericRange(
          epssMin,
          epssMax,
          defaultEpssRange,
          (value) =>
            Math.min(Math.max(value, defaultEpssRange[0]), defaultEpssRange[1]),
        );

  if (
    epssRange.value[0] !== nextEpssRange[0] ||
    epssRange.value[1] !== nextEpssRange[1]
  ) {
    epssRange.value = nextEpssRange;
  }

  const priceMin = parseQueryFloat(getValue("priceMin"));
  const priceMax = parseQueryFloat(getValue("priceMax"));
  const [defaultPriceMin, defaultPriceMax] = defaultPriceRange.value;
  const nextPriceRange =
    priceMin === null && priceMax === null
      ? [defaultPriceMin, defaultPriceMax]
      : normaliseNumericRange(
          priceMin,
          priceMax,
          [defaultPriceMin, defaultPriceMax],
          (value) => {
            const [minDefault, maxDefault] = defaultPriceRange.value;
            return Math.min(Math.max(value, minDefault), maxDefault);
          },
        );

  if (priceSliderReady.value) {
    if (
      priceRange.value[0] !== nextPriceRange[0] ||
      priceRange.value[1] !== nextPriceRange[1]
    ) {
      priceRange.value = [nextPriceRange[0], nextPriceRange[1]];
    }
    priceRangeInitialised = true;
    pendingPriceRange = null;
  } else {
    pendingPriceRange = [nextPriceRange[0], nextPriceRange[1]];
    priceRangeInitialised = false;
  }

  const sourceParam = extractQueryString(getValue("source"));
  let resolvedSource: typeof selectedSource.value = "all";
  if (
    sourceParam === "kev" ||
    sourceParam === "enisa" ||
    sourceParam === "historic" ||
    sourceParam === "metasploit" ||
    sourceParam === "poc"
  ) {
    resolvedSource = sourceParam;
  }

  if (selectedSource.value !== resolvedSource) {
    selectedSource.value = resolvedSource;
  }

  const marketProgramTypeParam = extractQueryString(getValue("marketProgramType"));
  const resolvedMarketProgramType: MarketProgramType | null =
    marketProgramTypeParam === "exploit-broker" ||
    marketProgramTypeParam === "bug-bounty" ||
    marketProgramTypeParam === "other"
      ? marketProgramTypeParam
      : null;

  if (selectedMarketProgramType.value !== resolvedMarketProgramType) {
    selectedMarketProgramType.value = resolvedMarketProgramType;
  }

  const updateBooleanFlag = (
    target: { value: boolean },
    key: string,
    fallback: boolean,
  ) => {
    const parsed = parseQueryBoolean(getValue(key));
    const nextValue = parsed ?? fallback;

    if (target.value !== nextValue) {
      target.value = nextValue;
    }
  };

  updateBooleanFlag(showWellKnownOnly, "wellKnownOnly", false);
  updateBooleanFlag(showRansomwareOnly, "ransomwareOnly", false);
  updateBooleanFlag(showInternetExposedOnly, "internetExposedOnly", false);
  updateBooleanFlag(showPublicExploitOnly, "publicExploitOnly", false);

  const ownedOnly =
    parseQueryBoolean(getValue("ownedOnly")) ??
    parseQueryBoolean(getValue("showOwnedOnly")) ??
    false;
  if (showOwnedOnly.value !== ownedOnly) {
    showOwnedOnly.value = ownedOnly;
  }

  updateBooleanFlag(showAllResults, "showAllResults", true);

  const sortParam = extractQueryString(getValue("sort"));
  const resolvedSort: SortOption =
    sortParam === "cvssScore" ||
    sortParam === "epssScore" ||
    sortParam === "cveId" ||
    sortParam === "publicationDate"
      ? sortParam
      : "publicationDate";

  if (sortOption.value !== resolvedSort) {
    sortOption.value = resolvedSort;
  }

  const directionParam = extractQueryString(getValue("sortDirection"));
  const resolvedDirection: SortDirection =
    directionParam === "asc" || directionParam === "desc"
      ? directionParam
      : "desc";

  if (sortDirection.value !== resolvedDirection) {
    sortDirection.value = resolvedDirection;
  }
};

const toRouteQueryRecord = (source: RouteQuery): Record<string, string> => {
  const record: Record<string, string> = {};

  for (const [key, rawValue] of Object.entries(source)) {
    if (Array.isArray(rawValue)) {
      if (!rawValue.length) {
        continue;
      }

      const candidate = rawValue[rawValue.length - 1];
      if (typeof candidate === "string") {
        record[key] = candidate;
      } else if (typeof candidate === "number" || typeof candidate === "boolean") {
        record[key] = String(candidate);
      }

      continue;
    }

    if (typeof rawValue === "string") {
      record[key] = rawValue;
    } else if (typeof rawValue === "number" || typeof rawValue === "boolean") {
      record[key] = String(rawValue);
    }
  }

  return record;
};

const areRouteQueryRecordsEqual = (
  first: Record<string, string>,
  second: Record<string, string>,
) => {
  const firstKeys = Object.keys(first);
  const secondKeys = Object.keys(second);

  if (firstKeys.length !== secondKeys.length) {
    return false;
  }

  return firstKeys.every((key) => first[key] === second[key]);
};


const {
  trackedProducts,
  trackedProductSet,
  addTrackedProduct,
  removeTrackedProduct,
  clearTrackedProducts,
  showOwnedOnly,
  isSaving: savingTrackedProducts,
  saveError: trackedProductError,
  isReady: trackedProductsReady,
  connectKevData: connectTrackedProductsKevData,
  trackedProductInsights,
  trackedProductSummary,
  recentWindowDays: trackedRecentWindowDays,
} = useTrackedProducts();

const routeQueryState = computed<Record<string, string>>(() => {
  const query: Record<string, string> = {};
  const searchTerm = debouncedSearch.value.trim();

  if (searchTerm) {
    query.search = searchTerm;
  }

  (Object.entries(filters) as Array<[FilterKey, string | null]>).forEach(
    ([key, value]) => {
      if (value) {
        query[key] = value;
      }
    },
  );

  const [defaultStartYear, defaultEndYear] = defaultYearRange.value;
  const [currentStartYear, currentEndYear] = yearRange.value;
  if (
    currentStartYear !== defaultStartYear ||
    currentEndYear !== defaultEndYear
  ) {
    query.startYear = String(currentStartYear);
    query.endYear = String(currentEndYear);
  }

  const [currentCvssMin, currentCvssMax] = cvssRange.value;
  if (
    currentCvssMin !== defaultCvssRange[0] ||
    currentCvssMax !== defaultCvssRange[1]
  ) {
    query.cvssMin = String(currentCvssMin);
    query.cvssMax = String(currentCvssMax);
  }

  const [currentEpssMin, currentEpssMax] = epssRange.value;
  if (
    currentEpssMin !== defaultEpssRange[0] ||
    currentEpssMax !== defaultEpssRange[1]
  ) {
    query.epssMin = String(currentEpssMin);
    query.epssMax = String(currentEpssMax);
  }

  if (priceSliderReady.value) {
    const [defaultPriceMin, defaultPriceMax] = defaultPriceRange.value;
    const [currentPriceMin, currentPriceMax] = priceRange.value;
    if (
      currentPriceMin !== defaultPriceMin ||
      currentPriceMax !== defaultPriceMax
    ) {
      query.priceMin = String(Math.round(currentPriceMin));
      query.priceMax = String(Math.round(currentPriceMax));
    }
  }

  if (selectedSource.value !== "all") {
    query.source = selectedSource.value;
  }

  if (selectedMarketProgramType.value) {
    query.marketProgramType = selectedMarketProgramType.value;
  }

  if (showWellKnownOnly.value) {
    query.wellKnownOnly = "true";
  }

  if (showRansomwareOnly.value) {
    query.ransomwareOnly = "true";
  }

  if (showPublicExploitOnly.value) {
    query.publicExploitOnly = "true";
  }

  if (showInternetExposedOnly.value) {
    query.internetExposedOnly = "true";
  }

  if (showOwnedOnly.value) {
    query.ownedOnly = "true";
  }

  if (!showAllResults.value) {
    query.showAllResults = "false";
  }

  if (sortOption.value !== "publicationDate") {
    query.sort = sortOption.value;
  }

  if (sortDirection.value !== "desc") {
    query.sortDirection = sortDirection.value;
  }

  return query;
});

let hasAppliedInitialRoute = false;
let isApplyingRouteToState = false;
let isReplacingRouteQuery = false;

watch(
  () => route.query,
  (next) => {
    if (isReplacingRouteQuery) {
      return;
    }

    isApplyingRouteToState = true;
    applyRouteQueryState(next as RouteQuery);
    isApplyingRouteToState = false;
    hasAppliedInitialRoute = true;
  },
  { immediate: true, deep: true },
);

watch(
  routeQueryState,
  (next) => {
    if (!hasAppliedInitialRoute || isApplyingRouteToState) {
      return;
    }

    const current = toRouteQueryRecord(route.query as RouteQuery);
    if (areRouteQueryRecordsEqual(current, next)) {
      return;
    }

    isReplacingRouteQuery = true;
    router
      .replace({ query: next })
      .finally(() => {
        isReplacingRouteQuery = false;
      });
  },
  { deep: true },
);

const trackedProductKeys = computed(() =>
  trackedProducts.value.map((item) => item.productKey)
);

const trackedProductCount = computed(() => trackedProductKeys.value.length);

const hasTrackedProducts = computed(() => trackedProductCount.value > 0);

const latestTrackedInsightDate = computed<Date | null>(() => {
  let latest: Date | null = null;

  for (const insight of trackedProductInsights.value) {
    if (!insight.latestAddedAt) {
      continue;
    }

    const parsed = parseISO(insight.latestAddedAt);
    if (Number.isNaN(parsed.getTime())) {
      continue;
    }

    if (!latest || parsed.getTime() > latest.getTime()) {
      latest = parsed;
    }
  }

  return latest;
});

const showOwnedOnlyEffective = computed(
  () => trackedProductsReady.value && showOwnedOnly.value
);

const productMetaMap = computed(() => {
  const map = new Map<
    string,
    {
      productKey: string;
      productName: string;
      vendorKey: string;
      vendorName: string;
    }
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
    publicExploitOnly: showPublicExploitOnly.value ? true : undefined,
    ownedOnly: showOwnedOnlyEffective.value ? true : undefined,
    internetExposedOnly: showInternetExposedOnly.value ? true : undefined,
  };

  if (showOwnedOnlyEffective.value && trackedProductKeys.value.length) {
    params.products = trackedProductKeys.value.join(",");
  }

  if (selectedSource.value !== "all") {
    params.source = selectedSource.value;
  }

  if (selectedMarketProgramType.value) {
    params.marketProgramType = selectedMarketProgramType.value;
  }

  if (cvssStart > defaultCvssRange[0] || cvssEnd < defaultCvssRange[1]) {
    params.cvssMin = cvssStart;
    params.cvssMax = cvssEnd;
  }

  if (epssStart > defaultEpssRange[0] || epssEnd < defaultEpssRange[1]) {
    params.epssMin = epssStart;
    params.epssMax = epssEnd;
  }

  if (priceSliderReady.value) {
    const [defaultPriceMin, defaultPriceMax] = defaultPriceRange.value;
    const [currentPriceMin, currentPriceMax] = priceRange.value;
    if (
      currentPriceMin > defaultPriceMin ||
      currentPriceMax < defaultPriceMax
    ) {
      params.priceMin = currentPriceMin;
      params.priceMax = currentPriceMax;
    }
  }

  if (showAllResults.value) {
    params.limit = maxEntryLimit;
  }

  return params;
});

const normalizedSearchTerm = computed(() =>
  debouncedSearch.value.trim().toLowerCase()
);

const {
  entries,
  counts,
  catalogBounds,
  updatedAt,
  getWellKnownCveName,
  totalEntries,
  totalEntriesWithoutYear,
  entryLimit,
  pending: dataPending,
  market: marketOverview,
} = useKevData(filterParams);

const {
  currencyFormatter,
  defaultPriceRange: marketDefaultPriceRange,
  filteredMarketPriceBounds,
  filteredMarketPriceSummary,
  marketCategoryCounts,
  marketOfferCount,
  marketPriceBounds: marketMetricsPriceBounds,
  marketProgramCounts,
} = useMarketMetrics(marketOverview);

watch(
  marketDefaultPriceRange,
  (next) => {
    defaultPriceRange.value = [next[0], next[1]];
  },
  { immediate: true },
);

watch(
  marketMetricsPriceBounds,
  (next) => {
    if (!next) {
      marketPriceBounds.value = { minRewardUsd: null, maxRewardUsd: null };
      return;
    }

    marketPriceBounds.value = {
      minRewardUsd: next.minRewardUsd,
      maxRewardUsd: next.maxRewardUsd,
    };
  },
  { immediate: true },
);

watch(
  defaultPriceRange,
  (next) => {
    if (!priceSliderReady.value) {
      return;
    }

    if (!priceRangeInitialised) {
      priceRange.value = [next[0], next[1]];
      priceRangeInitialised = true;
      pendingPriceRange = null;
      return;
    }

    const [currentMin, currentMax] = priceRange.value;
    let nextMin = currentMin;
    let nextMax = currentMax;

    if (currentMin < next[0]) {
      nextMin = next[0];
    }
    if (currentMax > next[1]) {
      nextMax = next[1];
    }

    if (nextMin > nextMax) {
      nextMin = next[0];
      nextMax = next[1];
    }

    if (nextMin !== currentMin || nextMax !== currentMax) {
      priceRange.value = [nextMin, nextMax];
    }
  },
  { immediate: true }
);

watch(priceSliderReady, (ready) => {
  if (ready) {
    const target = pendingPriceRange ?? defaultPriceRange.value;
    priceRange.value = [target[0], target[1]];
    priceRangeInitialised = true;
    pendingPriceRange = null;
  }
});

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

const isYearRangeLimited = computed(() => {
  const [start, end] = yearRange.value;
  const [min, max] = yearBounds.value;
  return start > min || end < max;
});

watch(
  yearBounds,
  ([min, max]) => {
    const hadCustomRange = hasCustomYearRange.value;

    const [defaultStart, defaultEnd] = defaultYearRange.value;
    const nextDefaultStart = Math.min(Math.max(defaultStart, min), max);
    const nextDefaultEnd = Math.min(Math.max(defaultEnd, min), max);
    const defaultChanged =
      nextDefaultStart !== defaultStart || nextDefaultEnd !== defaultEnd;

    if (defaultChanged) {
      defaultYearRange.value = [nextDefaultStart, nextDefaultEnd];
    }

    if (!hadCustomRange || defaultChanged) {
      yearRange.value = [
        defaultYearRange.value[0],
        defaultYearRange.value[1],
      ];
      return;
    }

    const [currentStart, currentEnd] = yearRange.value;
    let nextStart = Math.min(Math.max(currentStart, min), max);
    let nextEnd = Math.min(Math.max(currentEnd, min), max);

    if (nextStart > nextEnd) {
      yearRange.value = [
        defaultYearRange.value[0],
        defaultYearRange.value[1],
      ];
      return;
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
    cvssRange.value[0] > defaultCvssRange[0] ||
    cvssRange.value[1] < defaultCvssRange[1];
  const hasEpssFilter =
    epssRange.value[0] > defaultEpssRange[0] ||
    epssRange.value[1] < defaultEpssRange[1];
  const hasSourceFilter = selectedSource.value !== "all";
  const hasTrackedFilter = showOwnedOnlyEffective.value;
  const hasMarketProgramFilter = Boolean(selectedMarketProgramType.value);

  return Boolean(
    hasSearch ||
      hasDomainFilters ||
      hasTrackedFilter ||
      showWellKnownOnly.value ||
      showPublicExploitOnly.value ||
      showInternetExposedOnly.value ||
      hasCustomYearRange.value ||
      hasCvssFilter ||
      hasEpssFilter ||
      hasSourceFilter ||
      hasMarketProgramFilter
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

const cvssSeverityColors: Record<
  Exclude<KevEntrySummary["cvssSeverity"], null>,
  string
> = {
  None: "success",
  Low: "primary",
  Medium: "warning",
  High: "error",
  Critical: "error",
};


const formatCvssScore = (score: number | null) =>
  typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : null;

const formatEpssScore = (score: number | null) =>
  typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : null;

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
const detailEntry = ref<KevEntryDetail | null>(null);
const detailLoading = ref(false);
const detailError = ref<string | null>(null);
const detailCache = new Map<string, KevEntryDetail>();

const createDetailPlaceholder = (entry: KevEntrySummary): KevEntryDetail => ({
  ...entry,
  requiredAction: null,
  dueDate: null,
  notes: [],
  cwes: [],
  affectedProducts: [],
  problemTypes: [],
  cvssVector: null,
  cvssVersion: null,
  assigner: null,
  datePublished: entry.datePublished ?? null,
  dateUpdated: null,
  exploitedSince: null,
  sourceUrl: null,
  pocUrl: null,
  references: [],
  aliases: [],
  metasploitModulePath: null,
  timeline: [],
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
    const response = await $fetch<KevEntryDetail>(`/api/kev/${entry.id}`);
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

const handleTableSelect = (row: TableRow<KevEntrySummary>) => {
  openDetails(row.original);
};

const closeDetails = () => {
  showDetails.value = false;
};

const handleDetailQuickFilter = (update: QuickFilterUpdate) => {
  applyQuickFilters(update);
  closeDetails();
};

const handleCatalogHeatmapQuickFilter = (update: QuickFilterUpdate) => {
  applyQuickFilters(update);
};

const handleTrendQuickFilter = (update: QuickFilterUpdate) => {
  applyQuickFilters(update);
  showTrendSlideover.value = false;
};

const handleTrackedInsightQuickFilter = (
  target: TrackedProductQuickFilterTarget,
) => {
  if (!target?.product) {
    return;
  }

  const anchor = target.latestAddedAt ? parseISO(target.latestAddedAt) : null;
  const yearRange = computeTrackedYearRange(
    anchor,
    target.recentWindowDays ?? null,
  );

  applyQuickFilters({
    filters: {
      vendor: target.product.vendorKey,
      product: target.product.productKey,
    },
    ...(yearRange ? { yearRange } : {}),
    showOwnedOnly: true,
  });

  showMySoftwareSlideover.value = false;
};

const handleTrackedSummaryQuickFilter = () => {
  if (!hasTrackedProducts.value) {
    return;
  }

  const yearRange = computeTrackedYearRange(
    latestTrackedInsightDate.value,
    trackedRecentWindowDays.value ?? null,
  );

  applyQuickFilters({
    filters: {
      vendor: null,
      product: null,
    },
    ...(yearRange ? { yearRange } : {}),
    showOwnedOnly: true,
  });

  showMySoftwareSlideover.value = false;
};

const handleAddToTracked = (entry: KevEntrySummary) => {
  addTrackedProduct({
    productKey: entry.productKey,
    productName: entry.product,
    vendorKey: entry.vendorKey,
    vendorName: entry.vendor,
  });
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

connectTrackedProductsKevData({
  entries,
  productCounts,
});

const getPublicationTimestamp = (entry: KevEntrySummary) => {
  const candidates = [entry.datePublished, entry.dateAdded];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    const parsed = Date.parse(candidate);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }

  return null;
};

const compareNullableNumbers = (
  firstValue: number | null | undefined,
  secondValue: number | null | undefined,
  direction: SortDirection
) => {
  const firstHas = typeof firstValue === "number" && Number.isFinite(firstValue);
  const secondHas = typeof secondValue === "number" && Number.isFinite(secondValue);

  if (!firstHas && !secondHas) {
    return 0;
  }

  if (!firstHas) {
    return 1;
  }

  if (!secondHas) {
    return -1;
  }

  return direction === "asc"
    ? firstValue - secondValue
    : secondValue - firstValue;
};

const applySorting = (collection: KevEntrySummary[]) => {
  const sorted = [...collection];
  const direction = sortDirection.value;

  sorted.sort((first, second) => {
    switch (sortOption.value) {
      case "epssScore":
        return compareNullableNumbers(first.epssScore, second.epssScore, direction);
      case "cvssScore":
        return compareNullableNumbers(first.cvssScore, second.cvssScore, direction);
      case "cveId": {
        const firstId = first.cveId ?? "";
        const secondId = second.cveId ?? "";

        if (!firstId && !secondId) {
          return 0;
        }

        if (!firstId) {
          return 1;
        }

        if (!secondId) {
          return -1;
        }

        return direction === "asc"
          ? firstId.localeCompare(secondId)
          : secondId.localeCompare(firstId);
      }
      case "publicationDate":
      default: {
        const firstTimestamp = getPublicationTimestamp(first);
        const secondTimestamp = getPublicationTimestamp(second);

        if (firstTimestamp === null && secondTimestamp === null) {
          return 0;
        }

        if (firstTimestamp === null) {
          return 1;
        }

        if (secondTimestamp === null) {
          return -1;
        }

        return direction === "asc"
          ? firstTimestamp - secondTimestamp
          : secondTimestamp - firstTimestamp;
      }
    }
  });

  return sorted;
};

const results = computed(() => {
  const term = normalizedSearchTerm.value;
  const trackedKeys = trackedProductSet.value;

  let collection = entries.value;

  if (showOwnedOnlyEffective.value) {
    if (!trackedKeys.size) {
      return [];
    }

    collection = collection.filter((entry) =>
      trackedKeys.has(entry.productKey)
    );
  }

  if (term) {
    const includesTerm = (value: string | null | undefined) =>
      typeof value === "string" && value.toLowerCase().includes(term);

    collection = collection.filter((entry) => {
      const aliasMatch = Array.isArray(entry.aliases)
        ? entry.aliases.some((alias) => includesTerm(alias))
        : false;
      const wellKnownName = getWellKnownCveName(entry.cveId);

      return (
        includesTerm(entry.cveId) ||
        includesTerm(entry.vendor) ||
        includesTerm(entry.product) ||
        includesTerm(entry.vulnerabilityName) ||
        includesTerm(entry.description) ||
        aliasMatch ||
        (typeof wellKnownName === "string" && includesTerm(wellKnownName))
      );
    });
  }

  return applySorting(collection);
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

watch(
  [results, () => pagination.value.pageSize],
  () => {
    nextTick(() => {
      const tableApi = table.value?.tableApi;
      if (!tableApi) {
        return;
      }

      const { pageIndex } = tableApi.getState().pagination;
      const maxPageIndex = Math.max(0, tableApi.getPageCount() - 1);

      if (pageIndex > maxPageIndex) {
        tableApi.setPageIndex(Math.max(0, maxPageIndex));
      }
    });
  },
  { flush: "post" }
);

const handlePageUpdate = (page: number) => {
  const nextIndex = Math.max(0, page - 1);
  const tableApi = table.value?.tableApi;

  if (tableApi) {
    tableApi.setPageIndex(nextIndex);
    return;
  }

  pagination.value.pageIndex = nextIndex;
};

const isBusy = computed(() => dataPending.value || isFiltering.value);

const paginatedRowStartIndex = computed(() => {
  if (!results.value.length) {
    return 0;
  }

  const start = pagination.value.pageIndex * pagination.value.pageSize;
  return Math.min(start, Math.max(results.value.length - 1, 0));
});

const paginatedRowEndIndex = computed(() => {
  if (!results.value.length) {
    return 0;
  }

  return Math.min(
    paginatedRowStartIndex.value + pagination.value.pageSize,
    results.value.length,
  );
});

const visiblePageRowCount = computed(() => {
  if (!results.value.length) {
    return 0;
  }

  return paginatedRowEndIndex.value - paginatedRowStartIndex.value;
});

const shownResultCount = computed(() => results.value.length);
const totalMatchCount = computed(() => totalEntries.value);
const hasLimitedResults = computed(
  () =>
    totalMatchCount.value > entryLimit.value ||
    (showAllResults.value && shownResultCount.value < totalMatchCount.value)
);
const canShowAllResults = computed(
  () => hasLimitedResults.value || showAllResults.value
);
const resultCountLabel = computed(() => {
  const total = totalMatchCount.value;
  const loaded = shownResultCount.value;
  const visible = visiblePageRowCount.value;

  if (total === 0) {
    return "No matches found.";
  }

  if (!loaded || !visible) {
    return `Showing 0 of ${total.toLocaleString()} matches.`;
  }

  if (
    total <= loaded &&
    loaded <= pagination.value.pageSize &&
    paginatedRowStartIndex.value === 0 &&
    paginatedRowEndIndex.value === loaded
  ) {
    const shownLabel = `${loaded.toLocaleString()} match${
      loaded === 1 ? "" : "es"
    }`;
    return `Showing ${shownLabel}.`;
  }

  const start = paginatedRowStartIndex.value + 1;
  const end = paginatedRowEndIndex.value;
  const rangeLabel =
    start === end
      ? start.toLocaleString()
      : `${start.toLocaleString()}–${end.toLocaleString()}`;

  return `Showing ${rangeLabel} of ${total.toLocaleString()} matches.`;
});

watch(showTrendSlideover, (value) => {
  if (value) {
    showTrendLines.value = true;
  }
});

const resetYearRange = () => {
  const [start, end] = defaultYearRange.value;
  yearRange.value = [start, end];
};

const clearYearRange = () => {
  const [min, max] = yearBounds.value;
  yearRange.value = [min, max];
};

const handleQuickYearRangeUpdate = (value: [number, number]) => {
  yearRange.value = [value[0], value[1]];
};

const handleQuickSearchUpdate = (value: string) => {
  searchInput.value = value;
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
  showPublicExploitOnly.value = false;
  showOwnedOnly.value = false;
  showAllResults.value = true;
  cvssRange.value = [defaultCvssRange[0], defaultCvssRange[1]];
  epssRange.value = [defaultEpssRange[0], defaultEpssRange[1]];
  selectedSource.value = "all";
  selectedMarketProgramType.value = null;
  resetYearRange();
  if (priceSliderReady.value) {
    const [min, max] = defaultPriceRange.value;
    priceRange.value = [min, max];
  } else {
    priceRange.value = [0, 0];
    priceRangeInitialised = false;
    pendingPriceRange = null;
  }
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
    return {
      count: 0,
      percent: null as number | null,
      percentLabel: null as string | null,
    };
  }

  const percent = (count / total) * 100;
  return {
    count,
    percent,
    percentLabel: percentFormatter.format(percent),
  };
};

const matchingResultsCount = computed(() => results.value.length);
const matchingResultsLabel = computed(() =>
  matchingResultsCount.value.toLocaleString()
);

const showCatalogEmptyState = computed(
  () => !isBusy.value && results.value.length === 0
);

watch(showCatalogEmptyState, (value) => {
  if (value) {
    showHeatmap.value = false;
  }
});

const hasMatchesOutsideYearRange = computed(() => {
  if (!showCatalogEmptyState.value) {
    return false;
  }

  if (!isYearRangeLimited.value) {
    return false;
  }

  if (dataPending.value) {
    return false;
  }

  return totalEntriesWithoutYear.value > 0;
});

const catalogEmptyMessage = computed(() => {
  if (hasMatchesOutsideYearRange.value) {
    return `No vulnerabilities match these filters within ${quickFilterYearLabel.value}, but matches exist outside this timeframe. Expand the year filter to include more years.`;
  }

  return "No vulnerabilities match the current filters.";
});

const riskFocusContext = computed(() => ({
  active: showOwnedOnlyEffective.value && hasTrackedProducts.value,
  summary: trackedProductSummary.value,
}));

type AggregatedMetrics = {
  totalCount: number;
  ransomwareCount: number;
  cvssSum: number;
  cvssCount: number;
  severeCount: number;
  internetExposedCount: number;
  latestEntry: KevEntrySummary | null;
  latestTimestamp: number;
};

type PeriodMetrics = {
  totalCount: number;
  ransomwareCount: number;
  cvssSum: number;
  cvssCount: number;
  severeCount: number;
  internetExposedCount: number;
};

type PeriodSnapshot = {
  current: PeriodMetrics;
  previous: PeriodMetrics;
  latestEntries: KevEntrySummary[];
};

const severityDisplayMeta: Record<
  SeverityKey,
  { label: string; color: string }
> = {
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
  period: PeriodSnapshot;
};

const derivedResultSnapshot = computed<DerivedResultSnapshot>(() => {
  const metrics: AggregatedMetrics = {
    totalCount: 0,
    ransomwareCount: 0,
    cvssSum: 0,
    cvssCount: 0,
    severeCount: 0,
    internetExposedCount: 0,
    latestEntry: null,
    latestTimestamp: Number.NEGATIVE_INFINITY,
  };

  const severityCounts = new Map<SeverityKey, number>();
  const timedEntries: Array<{ entry: KevEntrySummary; timestamp: number }> = [];

  for (const entry of results.value) {
    metrics.totalCount += 1;
    const severity = entry.cvssSeverity;
    if (severity === "High" || severity === "Critical") {
      metrics.severeCount += 1;
    }

    if (
      typeof entry.cvssScore === "number" &&
      Number.isFinite(entry.cvssScore)
    ) {
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
      timedEntries.push({ entry, timestamp });
      if (timestamp > metrics.latestTimestamp) {
        metrics.latestTimestamp = timestamp;
        metrics.latestEntry = entry;
      }
    }
  }

  timedEntries.sort((first, second) => second.timestamp - first.timestamp);

  const latestEntries = timedEntries
    .slice(0, latestAdditionLimit)
    .map((item) => item.entry);

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

  const createPeriodMetrics = (): PeriodMetrics => ({
    totalCount: 0,
    ransomwareCount: 0,
    cvssSum: 0,
    cvssCount: 0,
    severeCount: 0,
    internetExposedCount: 0,
  });

  const accumulatePeriodMetrics = (
    target: PeriodMetrics,
    entry: KevEntrySummary
  ) => {
    target.totalCount += 1;

    if ((entry.ransomwareUse?.toLowerCase() ?? "").includes("known")) {
      target.ransomwareCount += 1;
    }

    if (entry.internetExposed) {
      target.internetExposedCount += 1;
    }

    if (entry.cvssSeverity === "High" || entry.cvssSeverity === "Critical") {
      target.severeCount += 1;
    }

    if (
      typeof entry.cvssScore === "number" &&
      Number.isFinite(entry.cvssScore)
    ) {
      target.cvssSum += entry.cvssScore;
      target.cvssCount += 1;
    }
  };

  const period: PeriodSnapshot = {
    current: createPeriodMetrics(),
    previous: createPeriodMetrics(),
    latestEntries: [],
  };

  if (timedEntries.length && Number.isFinite(metrics.latestTimestamp)) {
    const periodEnd = metrics.latestTimestamp;
    const periodStart = periodEnd - latestAdditionWindowMs;
    const previousEnd = periodStart - 1;
    const previousStart = previousEnd - latestAdditionWindowMs;

    const currentEntries: Array<{ entry: KevEntrySummary; timestamp: number }> = [];

    for (const item of timedEntries) {
      const { entry, timestamp } = item;
      if (timestamp >= periodStart && timestamp <= periodEnd) {
        accumulatePeriodMetrics(period.current, entry);
        currentEntries.push(item);
      } else if (timestamp >= previousStart && timestamp <= previousEnd) {
        accumulatePeriodMetrics(period.previous, entry);
      }
    }

    period.latestEntries = currentEntries
      .sort((first, second) => second.timestamp - first.timestamp)
      .slice(0, latestAdditionLimit)
      .map((item) => item.entry);
  }

  return {
    aggregated: metrics,
    severityDistribution,
    latestEntries,
    period,
  };
});

const riskPeriodSnapshot = computed(() => derivedResultSnapshot.value.period);
const currentPeriodMetrics = computed(
  () => riskPeriodSnapshot.value.current
);
const previousPeriodMetrics = computed(
  () => riskPeriodSnapshot.value.previous
);

const periodLabel = computed(() =>
  latestAdditionWindowDays === 1
    ? "Last day"
    : `Last ${latestAdditionWindowDays} days`
);
const periodDescriptor = computed(() =>
  latestAdditionWindowDays === 1
    ? "last day"
    : `last ${latestAdditionWindowDays} days`
);

const percentDeltaFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
  signDisplay: "always",
});
const scoreDeltaFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
  signDisplay: "always",
});

const computePercentTrend = (
  current: number | null,
  previous: number | null
): StatTrend | null => {
  if (current === null || previous === null) {
    return null;
  }

  const delta = current - previous;
  const direction = Math.abs(delta) < 0.1 ? "flat" : delta > 0 ? "up" : "down";
  const deltaLabel =
    direction === "flat" ? "0 pts" : `${percentDeltaFormatter.format(delta)} pts`;
  return { direction, deltaLabel };
};

const computeScoreTrend = (
  current: number | null,
  previous: number | null
): StatTrend | null => {
  if (current === null || previous === null) {
    return null;
  }

  const delta = current - previous;
  const direction = Math.abs(delta) < 0.05 ? "flat" : delta > 0 ? "up" : "down";
  const deltaLabel =
    direction === "flat" ? "0.0" : scoreDeltaFormatter.format(delta);
  return { direction, deltaLabel };
};

const highSeverityShare = computed(() =>
  formatShare(
    currentPeriodMetrics.value.severeCount,
    currentPeriodMetrics.value.totalCount
  )
);
const previousHighSeverityShare = computed(() =>
  formatShare(
    previousPeriodMetrics.value.severeCount,
    previousPeriodMetrics.value.totalCount
  )
);
const highSeverityShareLabel = computed(() => {
  const label = highSeverityShare.value.percentLabel;
  return label === null ? "—" : `${label}%`;
});
const highSeverityTrend = computed(() =>
  computePercentTrend(
    highSeverityShare.value.percent ?? null,
    previousHighSeverityShare.value.percent ?? null
  )
);
const highSeveritySummary = computed(() => {
  const total = currentPeriodMetrics.value.totalCount;
  const severe = currentPeriodMetrics.value.severeCount;

  if (!total) {
    return `No CVEs added in the ${periodDescriptor.value}.`;
  }

  if (!severe) {
    return `No high-severity CVEs in the ${periodDescriptor.value}.`;
  }

  return `${severe.toLocaleString()} of ${total.toLocaleString()} CVEs rated High or Critical in the ${periodDescriptor.value}.`;
});

const ransomwareShare = computed(() =>
  formatShare(
    currentPeriodMetrics.value.ransomwareCount,
    currentPeriodMetrics.value.totalCount
  )
);
const previousRansomwareShare = computed(() =>
  formatShare(
    previousPeriodMetrics.value.ransomwareCount,
    previousPeriodMetrics.value.totalCount
  )
);
const ransomwareShareLabel = computed(() => {
  const label = ransomwareShare.value.percentLabel;
  return label === null ? "—" : `${label}%`;
});
const ransomwareTrend = computed(() =>
  computePercentTrend(
    ransomwareShare.value.percent ?? null,
    previousRansomwareShare.value.percent ?? null
  )
);
const ransomwareSummary = computed(() => {
  const total = currentPeriodMetrics.value.totalCount;
  const count = currentPeriodMetrics.value.ransomwareCount;

  if (!total) {
    return `No CVEs added in the ${periodDescriptor.value}.`;
  }

  if (!count) {
    return `No ransomware intelligence in the ${periodDescriptor.value}.`;
  }

  return `${count.toLocaleString()} CVEs tied to ransomware activity in the ${periodDescriptor.value}.`;
});

const internetExposedShare = computed(() =>
  formatShare(
    currentPeriodMetrics.value.internetExposedCount,
    currentPeriodMetrics.value.totalCount
  )
);
const previousInternetExposedShare = computed(() =>
  formatShare(
    previousPeriodMetrics.value.internetExposedCount,
    previousPeriodMetrics.value.totalCount
  )
);
const internetExposedShareLabel = computed(() => {
  const label = internetExposedShare.value.percentLabel;
  return label === null ? "—" : `${label}%`;
});
const internetExposedTrend = computed(() =>
  computePercentTrend(
    internetExposedShare.value.percent ?? null,
    previousInternetExposedShare.value.percent ?? null
  )
);
const internetExposedSummary = computed(() => {
  const total = currentPeriodMetrics.value.totalCount;
  const count = currentPeriodMetrics.value.internetExposedCount;

  if (!total) {
    return `No CVEs added in the ${periodDescriptor.value}.`;
  }

  if (!count) {
    return `No confirmed internet-exposed CVEs in the ${periodDescriptor.value}.`;
  }

  return `${count.toLocaleString()} CVEs likely exposed to the internet in the ${periodDescriptor.value}.`;
});

const averageCvssScore = computed(() => {
  const { cvssSum, cvssCount } = currentPeriodMetrics.value;
  if (!cvssCount) {
    return null;
  }

  return cvssSum / cvssCount;
});
const previousAverageCvssScore = computed(() => {
  const { cvssSum, cvssCount } = previousPeriodMetrics.value;
  if (!cvssCount) {
    return null;
  }

  return cvssSum / cvssCount;
});
const averageCvssLabel = computed(() => {
  const value = averageCvssScore.value;
  return value === null ? "—" : value.toFixed(1);
});
const averageCvssTrend = computed(() =>
  computeScoreTrend(averageCvssScore.value, previousAverageCvssScore.value)
);
const averageCvssSummary = computed(() => {
  const count = currentPeriodMetrics.value.cvssCount;
  const total = currentPeriodMetrics.value.totalCount;

  if (!total) {
    return `No CVEs added in the ${periodDescriptor.value}.`;
  }

  if (!count) {
    return `No CVSS scores available in the ${periodDescriptor.value}.`;
  }

  return `Mean calculated from ${count.toLocaleString()} scored CVEs in the ${periodDescriptor.value}.`;
});

type QuickStatItem = {
  key: QuickFilterSummaryMetricKey;
  icon: string;
  label: string;
  value: string;
};

const quickFilterSummaryConfig = computed(
  () => quickFilterSummaryConfigData.value ?? defaultQuickFilterSummaryConfig,
);

const quickFilterYearLabel = computed(() => {
  const [start, end] = yearRange.value;
  return start === end ? `${start}` : `${start}–${end}`;
});

const activeFiltersSummaryLabel = computed(() => {
  const count = activeFilterCount.value;
  if (!count) {
    return "None";
  }
  return count === 1 ? "1 active" : `${count} active`;
});

const quickFilterSummaryMetricMap = computed<
  Record<QuickFilterSummaryMetricKey, QuickStatItem>
>(() => {
  const info = quickFilterSummaryMetricInfo;
  return {
    count: {
      key: "count",
      icon: info.count.icon,
      label: info.count.label,
      value: `${matchingResultsLabel.value} CVEs`,
    },
    year: {
      key: "year",
      icon: info.year.icon,
      label: info.year.label,
      value: quickFilterYearLabel.value,
    },
    activeFilters: {
      key: "activeFilters",
      icon: info.activeFilters.icon,
      label: info.activeFilters.label,
      value: activeFiltersSummaryLabel.value,
    },
    highSeverityShare: {
      key: "highSeverityShare",
      icon: info.highSeverityShare.icon,
      label: info.highSeverityShare.label,
      value: highSeverityShareLabel.value,
    },
    averageCvss: {
      key: "averageCvss",
      icon: info.averageCvss.icon,
      label: info.averageCvss.label,
      value: averageCvssLabel.value,
    },
    ransomwareShare: {
      key: "ransomwareShare",
      icon: info.ransomwareShare.icon,
      label: info.ransomwareShare.label,
      value: ransomwareShareLabel.value,
    },
    internetExposedShare: {
      key: "internetExposedShare",
      icon: info.internetExposedShare.icon,
      label: info.internetExposedShare.label,
      value: internetExposedShareLabel.value,
    },
  };
});

const quickStatItems = computed(() => {
  const config = quickFilterSummaryConfig.value;
  const metrics = config.metrics.length ? config.metrics : defaultQuickFilterSummaryConfig.metrics;
  const map = quickFilterSummaryMetricMap.value;

  return metrics
    .map((key) => map[key])
    .filter((item): item is QuickStatItem => Boolean(item));
});

const showQuickFilterChips = computed(() => quickFilterSummaryConfig.value.showActiveFilterChips);
const showQuickFilterResetButton = computed(() => quickFilterSummaryConfig.value.showResetButton);

const hasActiveFilterChips = computed(() => activeFilters.value.length > 0);

const resolveYearWindowStart = computed(() =>
  Math.max(yearSliderMax.value - 1, yearSliderMin.value),
);

const filterPresets = computed<QuickFilterPreset[]>(() =>
  createFilterPresets({
    currentYear: yearSliderMax.value,
    previousYear: resolveYearWindowStart.value,
    defaultYearRange: [
      defaultYearRange.value[0],
      defaultYearRange.value[1],
    ],
    sliderBounds: [yearSliderMin.value, yearSliderMax.value],
    defaultCvssRange,
    defaultEpssRange,
  }),
);

const rangesEqual = (
  first: readonly [number, number],
  second: readonly [number, number],
) => first[0] === second[0] && first[1] === second[1];

const matchesPresetState = (update: QuickFilterUpdate) => {
  if (update.filters) {
    for (const [rawKey, rawValue] of Object.entries(update.filters) as Array<[
      FilterKey,
      string | null | undefined,
    ]>) {
      const key = rawKey as FilterKey;
      if ((filters[key] ?? null) !== (rawValue ?? null)) {
        return false;
      }
    }
  }

  if (update.source && selectedSource.value !== update.source) {
    return false;
  }

  if (Array.isArray(update.yearRange)) {
    if (!rangesEqual(yearRange.value, update.yearRange)) {
      return false;
    }
  } else if (typeof update.year === "number") {
    if (
      yearRange.value[0] !== update.year ||
      yearRange.value[1] !== update.year
    ) {
      return false;
    }
  }

  if (typeof update.search === "string") {
    if (debouncedSearch.value.trim() !== update.search.trim()) {
      return false;
    }
  }

  if (
    typeof update.showWellKnownOnly === "boolean" &&
    showWellKnownOnly.value !== update.showWellKnownOnly
  ) {
    return false;
  }

  if (
    typeof update.showRansomwareOnly === "boolean" &&
    showRansomwareOnly.value !== update.showRansomwareOnly
  ) {
    return false;
  }

  if (
    typeof update.showPublicExploitOnly === "boolean" &&
    showPublicExploitOnly.value !== update.showPublicExploitOnly
  ) {
    return false;
  }

  if (
    typeof update.showInternetExposedOnly === "boolean" &&
    showInternetExposedOnly.value !== update.showInternetExposedOnly
  ) {
    return false;
  }

  if (
    typeof update.showOwnedOnly === "boolean" &&
    showOwnedOnly.value !== update.showOwnedOnly
  ) {
    return false;
  }

  if (Array.isArray(update.cvssRange)) {
    if (!rangesEqual(cvssRange.value, update.cvssRange)) {
      return false;
    }
  }

  if (Array.isArray(update.epssRange)) {
    if (!rangesEqual(epssRange.value, update.epssRange)) {
      return false;
    }
  }

  if (
    typeof update.showAllResults === "boolean" &&
    showAllResults.value !== update.showAllResults
  ) {
    return false;
  }

  return true;
};

const activeFilterPresetIds = computed(() => {
  const active = new Set<string>();
  for (const preset of filterPresets.value) {
    if (matchesPresetState(preset.update)) {
      active.add(preset.id);
    }
  }
  return active;
});

const isFilterPresetActive = (presetId: string) =>
  activeFilterPresetIds.value.has(presetId);

const presetIconClassMap: Record<string, string> = {
  primary: "text-primary-500 dark:text-primary-400",
  secondary: "text-secondary-500 dark:text-secondary-400",
  warning: "text-amber-500 dark:text-amber-400",
  error: "text-red-500 dark:text-red-400",
  info: "text-sky-500 dark:text-sky-400",
  neutral: "text-neutral-500 dark:text-neutral-300",
};

const severityDistribution = computed(
  () => derivedResultSnapshot.value.severityDistribution
);

const latestPeriodEntries = computed(
  () => derivedResultSnapshot.value.period.latestEntries
);

const latestResultEntries = computed(() => {
  const periodEntries = latestPeriodEntries.value;
  if (periodEntries.length) {
    return periodEntries;
  }

  return derivedResultSnapshot.value.latestEntries;
});

const usingPeriodEntries = computed(
  () => latestPeriodEntries.value.length > 0
);

const sortedLatestAdditionEntries = computed(() => {
  const entries = [...latestResultEntries.value];

  switch (latestAdditionSortKey.value) {
    case "epss": {
      return entries
        .slice()
        .sort((first, second) => {
          const firstScore = typeof first.epssScore === "number" ? first.epssScore : -1;
          const secondScore = typeof second.epssScore === "number" ? second.epssScore : -1;
          return secondScore - firstScore;
        })
        .slice(0, latestAdditionLimit);
    }
    case "cvss": {
      return entries
        .slice()
        .sort((first, second) => {
          const firstScore =
            typeof first.cvssScore === "number" && Number.isFinite(first.cvssScore)
              ? first.cvssScore
              : -1;
          const secondScore =
            typeof second.cvssScore === "number" && Number.isFinite(second.cvssScore)
              ? second.cvssScore
              : -1;
          return secondScore - firstScore;
        })
        .slice(0, latestAdditionLimit);
    }
    case "recent":
    default: {
      return entries
        .slice()
        .sort((first, second) => {
          const firstTimestamp = Date.parse(first.dateAdded);
          const secondTimestamp = Date.parse(second.dateAdded);

          if (Number.isNaN(firstTimestamp) && Number.isNaN(secondTimestamp)) {
            return 0;
          }

          if (Number.isNaN(firstTimestamp)) {
            return 1;
          }

          if (Number.isNaN(secondTimestamp)) {
            return -1;
          }

          return secondTimestamp - firstTimestamp;
        })
        .slice(0, latestAdditionLimit);
    }
  }
});

const latestAdditionSummaries = computed<LatestAdditionSummary[]>(() => {
  const tracked = trackedProductSet.value;

  return sortedLatestAdditionEntries.value.map((entry) => {
    const timestamp = Date.parse(entry.dateAdded);
    return {
      entry,
      dateLabel: formatOptionalTimestamp(entry.dateAdded),
      vendorProduct: `${entry.vendor} · ${entry.product}`,
      wellKnown: getWellKnownCveName(entry.cveId),
      sources: entry.sources,
      internetExposed: entry.internetExposed,
      timestamp: Number.isNaN(timestamp) ? null : timestamp,
      isTracked: tracked.has(entry.productKey),
    };
  });
});

const latestAdditionNotes = computed(() => {
  const items = latestAdditionSummaries.value;
  const total = items.length;
  if (!total) {
    return [] as string[];
  }

  const contextQualifier = usingPeriodEntries.value
    ? "this period"
    : "in recent updates";

  const notes: string[] = [];

  const internetCount = items.filter((item) => item.internetExposed).length;
  if (internetCount) {
    notes.push(
      `${internetCount} of ${total} new CVEs ${contextQualifier} are internet-exposed.`
    );
  }

  const highSeverityCount = items.filter((item) => {
    const severity = item.entry.cvssSeverity;
    return severity === "High" || severity === "Critical";
  }).length;
  if (highSeverityCount) {
    notes.push(
      `${highSeverityCount} of ${total} new CVEs ${contextQualifier} are rated High or Critical.`
    );
  }

  const ransomwareCount = items.filter((item) => {
    const signal = item.entry.ransomwareUse?.toLowerCase() ?? "";
    return signal.includes("known") || signal.includes("active");
  }).length;
  if (ransomwareCount) {
    notes.push(
      `${ransomwareCount} new CVEs ${contextQualifier} mention ransomware operations.`
    );
  }

  const highEpssCount = items.filter(
    (item) => typeof item.entry.epssScore === "number" && item.entry.epssScore >= 0.7
  ).length;
  if (highEpssCount) {
    notes.push(
      `${highEpssCount} new CVEs ${contextQualifier} have EPSS ≥ 70%.`
    );
  }

  return notes.slice(0, 3);
});

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

const allDomainCategories = [
  "Web Applications",
  "Web Servers",
  "Non-Web Applications",
  "Mail Servers",
  "Browsers",
  "Operating Systems",
  "Networking & VPN",
  "Industrial Control Systems",
  "Cloud & SaaS",
  "Virtualization & Containers",
  "Database & Storage",
  "Security Appliances",
  "Internet Edge",
  "Other",
] as const satisfies readonly KevDomainCategory[];

const allExploitLayers = [
  "RCE · Client-side Memory Corruption",
  "RCE · Server-side Memory Corruption",
  "RCE · Client-side Non-memory",
  "RCE · Server-side Non-memory",
  "DoS · Client-side",
  "DoS · Server-side",
  "Mixed/Needs Review",
  "Auth Bypass · Edge",
  "Auth Bypass · Server-side",
  "Configuration Abuse",
  "Privilege Escalation",
  "Command Injection",
] as const satisfies readonly KevExploitLayer[];

const allVulnerabilityCategories = [
  "Remote Code Execution",
  "Memory Corruption",
  "Command Injection",
  "Authentication Bypass",
  "Information Disclosure",
  "Denial of Service",
  "Directory Traversal",
  "SQL Injection",
  "Cross-Site Scripting",
  "Server-Side Request Forgery",
  "Logic Flaw",
  "Other",
] as const satisfies readonly KevVulnerabilityCategory[];

const normaliseCategoryIdentifier = (value: string) =>
  value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-");

const computeMissingCategoryNames = (
  allCategories: readonly string[],
  counts: KevCountDatum[],
) => {
  if (!allCategories.length) {
    return [] as string[];
  }

  const present = new Set(
    counts
      .filter((item) => (item.count ?? 0) > 0)
      .flatMap((item) => [item.name, item.key])
      .filter(
        (value): value is string =>
          typeof value === "string" && value.trim().length > 0,
      )
      .map((value) => normaliseCategoryIdentifier(value)),
  );

  return allCategories.filter(
    (category) => !present.has(normaliseCategoryIdentifier(category)),
  );
};

const domainStats = computed(() => toProgressStats(domainCounts.value));
const exploitLayerStats = computed(() => toProgressStats(exploitCounts.value));
const vulnerabilityStats = computed(() =>
  toProgressStats(vulnerabilityCounts.value)
);
const vendorStats = computed(() => toProgressStats(vendorCounts.value));
const productStats = computed(() => toProgressStats(productCounts.value));

const domainMissingCategories = computed(() =>
  computeMissingCategoryNames(allDomainCategories, domainCounts.value)
);
const exploitMissingCategories = computed(() =>
  computeMissingCategoryNames(allExploitLayers, exploitCounts.value)
);
const vulnerabilityMissingCategories = computed(() =>
  computeMissingCategoryNames(allVulnerabilityCategories, vulnerabilityCounts.value)
);

const missingFilterSectionClass =
  "space-y-1 border-t border-dashed border-neutral-200/80 pt-2 text-[11px] text-neutral-500 dark:border-neutral-700/60 dark:text-neutral-400";
const missingFilterPillClass =
  "rounded-full border border-neutral-200/70 bg-white/80 px-2 py-0.5 text-[11px] font-medium text-neutral-500 shadow-sm dark:border-neutral-700/60 dark:bg-neutral-800/60 dark:text-neutral-400";

const topCountOptions = [5, 10, 15, 20];
const topCountItems: SelectMenuItem<number>[] = topCountOptions.map(
  (value) => ({
    label: `Top ${value}`,
    value,
  })
);

const topVendorCount = ref<number>(5);
const topProductCount = ref<number>(5);

const topVendorStats = computed(() =>
  vendorStats.value.slice(0, topVendorCount.value)
);
const topProductStats = computed(() =>
  productStats.value.slice(0, topProductCount.value)
);

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
const topVulnerabilityStat = computed(
  () => vulnerabilityStats.value[0] ?? null
);

const filterLabels: Record<FilterKey, string> = {
  domain: "Domain",
  exploit: "Exploit profile",
  vulnerability: "Vulnerability category",
  vendor: "Vendor",
  product: "Product",
};

const resolveFilterValueLabel = (key: FilterKey, value: string) => {
  if (key === "vendor") {
    const fromCounts = vendorCounts.value.find(
      (item) => item.key === value
    )?.name;
    if (fromCounts) {
      return fromCounts;
    }

    const fromProducts = productMetaMap.value.get(value)?.vendorName;
    return fromProducts ?? value;
  }

  if (key === "product") {
    const fromCounts = productCounts.value.find(
      (item) => item.key === value
    )?.name;
    if (fromCounts) {
      return fromCounts;
    }

    const fromMap = productMetaMap.value.get(value)?.productName;
    return fromMap ?? value;
  }

  return value;
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
    items.push({
      key: "ransomware",
      label: "Focus",
      value: "Ransomware-linked CVEs",
    });
  }

  if (showPublicExploitOnly.value) {
    items.push({
      key: "publicExploit",
      label: "Focus",
      value: "Public exploit coverage",
    });
  }

  if (showInternetExposedOnly.value) {
    items.push({
      key: "internet",
      label: "Focus",
      value: "Internet-exposed CVEs",
    });
  }

  if (showOwnedOnlyEffective.value) {
    const summary = hasTrackedProducts.value
      ? `${trackedProductCount.value} selected`
      : "No products yet";
    items.push({
      key: "owned",
      label: "Focus",
      value: `My software · ${summary}`,
    });
  }

  if (hasCustomYearRange.value) {
    items.push({
      key: "yearRange",
      label: "Year range",
      value: `${yearRange.value[0]}–${yearRange.value[1]}`,
    });
  }

  if (selectedSource.value !== "all") {
    const label = catalogSourceLabels[selectedSource.value as CatalogSource];
    items.push({ key: "source", label: "Source", value: label });
  }

  if (selectedMarketProgramType.value) {
    items.push({
      key: "marketProgramType",
      label: "Market coverage",
      value: formatMarketProgramTypeLabel(selectedMarketProgramType.value),
    });
  }

  if (
    cvssRange.value[0] > defaultCvssRange[0] ||
    cvssRange.value[1] < defaultCvssRange[1]
  ) {
    const [min, max] = cvssRange.value;
    items.push({
      key: "cvssRange",
      label: "CVSS",
      value: `${min.toFixed(1)} – ${max.toFixed(1)}`,
    });
  }

  if (
    epssRange.value[0] > defaultEpssRange[0] ||
    epssRange.value[1] < defaultEpssRange[1]
  ) {
    const [min, max] = epssRange.value;
    items.push({
      key: "epssRange",
      label: "EPSS",
      value: `${Math.round(min)} – ${Math.round(max)}`,
    });
  }

  if (
    priceSliderReady.value &&
    (priceRange.value[0] > defaultPriceRange.value[0] ||
      priceRange.value[1] < defaultPriceRange.value[1])
  ) {
    const [min, max] = priceRange.value;
    items.push({
      key: "priceRange",
      label: "Reward",
      value: `${currencyFormatter.format(min)} – ${currencyFormatter.format(max)}`,
    });
  }

  return items;
});

const activeFilterCount = computed(() => activeFilters.value.length);

const focusActiveCount = computed(
  () =>
    [
      showOwnedOnlyEffective.value,
      showWellKnownOnly.value,
      showRansomwareOnly.value,
      showInternetExposedOnly.value,
    ].filter(Boolean).length
);

type AsideAccordionItem = AccordionItem & {
  value: string;
  badgeColor?: string;
  badgeText?: string;
};

const asideAccordionValue = ref<string[]>([]);

const asideAccordionItems = computed<AsideAccordionItem[]>(() => [
  {
    value: "domain",
    label: "Domain coverage",
    slot: "domain",
    badgeColor: "primary",
    badgeText: domainTotalCount.value.toLocaleString(),
  },
  {
    value: "exploit",
    label: "Exploit dynamics",
    slot: "exploit",
    badgeColor: "primary",
    badgeText: exploitLayerTotalCount.value.toLocaleString(),
  },
  {
    value: "vulnerability",
    label: "Vulnerability mix",
    slot: "vulnerability",
    badgeColor: "primary",
    badgeText: vulnerabilityTotalCount.value.toLocaleString(),
  },
  {
    value: "top-vendors",
    label: "Top vendors",
    slot: "topVendors",
    badgeColor: "secondary",
    badgeText: vendorTotalCount.value.toLocaleString(),
  },
  {
    value: "top-products",
    label: "Top products",
    slot: "topProducts",
    badgeColor: "secondary",
    badgeText: productTotalCount.value.toLocaleString(),
  },
  {
    value: "filters",
    label: "Filters",
    slot: "filters",
    badgeColor: "warning",
    badgeText: activeFilterCount.value.toString(),
  },
  {
    value: "presets",
    label: "Filter presets",
    slot: "presets",
    badgeColor: "info",
    badgeText: filterPresets.value.length.toString(),
  },
  {
    value: "market",
    label: "Market signals",
    slot: "market",
    badgeColor: "info",
    badgeText: marketOfferCount.value.toLocaleString(),
  },
  {
    value: "sort",
    label: "Sort order",
    slot: "sort",
    badgeColor: "neutral",
    badgeText: sortBadgeText.value,
  },
  {
    value: "focus",
    label: "Focus controls",
    slot: "focus",
    badgeColor: "warning",
    badgeText: focusActiveCount.value.toString(),
  },
  {
    value: "my-software",
    label: "My software focus",
    slot: "mySoftware",
    badgeColor: "neutral",
    badgeText: trackedProductsReady.value
      ? trackedProductCount.value.toLocaleString()
      : "…",
  },
  {
    value: "trend",
    label: "Trend explorer",
    slot: "trend",
    badgeColor: "neutral",
    badgeText: results.value.length.toLocaleString(),
  },
]);

const toggleFilter = (key: FilterKey, value: string) => {
  filters[key] = filters[key] === value ? null : value;
};

const openAccordionSections = (...sections: string[]) => {
  if (!sections.length) {
    return;
  }

  const next = new Set(asideAccordionValue.value);
  for (const section of sections) {
    if (section) {
      next.add(section);
    }
  }

  asideAccordionValue.value = Array.from(next);
};

const toggleMarketProgramTypeFilter = (value: MarketProgramType) => {
  if (selectedMarketProgramType.value === value) {
    selectedMarketProgramType.value = null;
    return;
  }

  selectedMarketProgramType.value = value;
  openAccordionSections("market");
};

const applyQuickFilters = (update: QuickFilterUpdate) => {
  const {
    filters: filterUpdates,
    source,
    year,
    yearRange: yearRangeUpdate,
    search,
    showWellKnownOnly: nextWellKnownOnly,
    showRansomwareOnly: nextRansomwareOnly,
    showInternetExposedOnly: nextInternetExposedOnly,
    showPublicExploitOnly: nextPublicExploitOnly,
    showOwnedOnly: nextOwnedOnly,
    cvssRange: nextCvssRange,
    epssRange: nextEpssRange,
    priceRange: nextPriceRange,
    showAllResults: nextShowAllResults,
    marketProgramType,
  } = update;

  if (replaceFiltersOnQuickApply.value) {
    resetFilters();
  }

  if (typeof search === "string") {
    const trimmed = search.trim();
    searchInput.value = trimmed;
    debouncedSearch.value = trimmed;
  }

  if (filterUpdates) {
    for (const [rawKey, rawValue] of Object.entries(filterUpdates) as Array<[
      FilterKey,
      string | null | undefined,
    ]>) {
      const key = rawKey as FilterKey;
      filters[key] = rawValue ?? null;
    }
  }

  if (source) {
    selectedSource.value = source;
  }

  if (Array.isArray(yearRangeUpdate) && yearRangeUpdate.length === 2) {
    yearRange.value = [yearRangeUpdate[0], yearRangeUpdate[1]];
  } else if (typeof year === "number" && Number.isFinite(year)) {
    yearRange.value = [year, year];
  }

  if (Array.isArray(nextCvssRange) && nextCvssRange.length === 2) {
    cvssRange.value = [nextCvssRange[0], nextCvssRange[1]];
  }

  if (Array.isArray(nextEpssRange) && nextEpssRange.length === 2) {
    epssRange.value = [nextEpssRange[0], nextEpssRange[1]];
  }

  if (Array.isArray(nextPriceRange) && nextPriceRange.length === 2) {
    if (priceSliderReady.value) {
      priceRange.value = [nextPriceRange[0], nextPriceRange[1]];
      priceRangeInitialised = true;
      pendingPriceRange = null;
    } else {
      pendingPriceRange = [nextPriceRange[0], nextPriceRange[1]];
      priceRangeInitialised = false;
    }
  }

  if (typeof nextWellKnownOnly === "boolean") {
    showWellKnownOnly.value = nextWellKnownOnly;
  }

  if (typeof nextRansomwareOnly === "boolean") {
    showRansomwareOnly.value = nextRansomwareOnly;
  }

  if (typeof nextPublicExploitOnly === "boolean") {
    showPublicExploitOnly.value = nextPublicExploitOnly;
  }

  if (typeof nextInternetExposedOnly === "boolean") {
    showInternetExposedOnly.value = nextInternetExposedOnly;
  }

  if (typeof nextOwnedOnly === "boolean") {
    showOwnedOnly.value = nextOwnedOnly;
  }

  if (marketProgramType !== undefined) {
    if (
      marketProgramType === "exploit-broker" ||
      marketProgramType === "bug-bounty" ||
      marketProgramType === "other"
    ) {
      selectedMarketProgramType.value = marketProgramType;
    } else {
      selectedMarketProgramType.value = null;
    }
  }

  const sectionsToOpen = new Set<string>(["filters"]);

  if (filterUpdates?.domain) {
    sectionsToOpen.add("domain");
  }
  if (filterUpdates?.exploit) {
    sectionsToOpen.add("exploit");
  }
  if (filterUpdates?.vulnerability) {
    sectionsToOpen.add("vulnerability");
  }

  if (
    marketProgramType &&
    (marketProgramType === "exploit-broker" ||
      marketProgramType === "bug-bounty" ||
      marketProgramType === "other")
  ) {
    sectionsToOpen.add("market");
  }
  if (filterUpdates?.vendor) {
    sectionsToOpen.add("top-vendors");
  }
  if (filterUpdates?.product) {
    sectionsToOpen.add("top-products");
  }

  if (
    typeof nextWellKnownOnly === "boolean" ||
    typeof nextRansomwareOnly === "boolean" ||
    typeof nextPublicExploitOnly === "boolean" ||
    typeof nextInternetExposedOnly === "boolean" ||
    typeof nextOwnedOnly === "boolean"
  ) {
    sectionsToOpen.add("focus");
  }

  if (
    Array.isArray(nextCvssRange) ||
    Array.isArray(nextEpssRange) ||
    Array.isArray(nextPriceRange)
  ) {
    sectionsToOpen.add("filters");
  }

  if (typeof search === "string" && search.trim()) {
    sectionsToOpen.add("filters");
  }

  if (Array.isArray(yearRangeUpdate) || typeof year === "number") {
    sectionsToOpen.add("filters");
  }

  openAccordionSections(...Array.from(sectionsToOpen));

  if (typeof nextShowAllResults === "boolean") {
    showAllResults.value = nextShowAllResults;
  } else {
    showAllResults.value = true;
  }
};

const computeTrackedYearRange = (
  anchor: Date | null,
  windowDays: number | null,
): [number, number] | null => {
  const fallback = anchor && !Number.isNaN(anchor.getTime()) ? anchor : new Date();
  if (Number.isNaN(fallback.getTime())) {
    return null;
  }

  let start = fallback;
  if (typeof windowDays === "number" && Number.isFinite(windowDays) && windowDays > 0) {
    start = new Date(fallback.getTime() - windowDays * 24 * 60 * 60 * 1000);
  }

  let startYear = start.getFullYear();
  let endYear = fallback.getFullYear();

  if (Number.isNaN(startYear)) {
    startYear = endYear;
  }

  if (Number.isNaN(endYear)) {
    return null;
  }

  if (startYear > endYear) {
    startYear = endYear;
  }

  startYear = Math.max(sliderMinYear, Math.min(sliderMaxYear, startYear));
  endYear = Math.max(startYear, Math.min(sliderMaxYear, endYear));

  return [startYear, endYear];
};

const handleApplyFilterPreset = (preset: QuickFilterPreset) => {
  applyQuickFilters(preset.update);
  openAccordionSections("presets");
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
    | "publicExploit"
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
    clearYearRange();
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

  if (key === "priceRange") {
    if (priceSliderReady.value) {
      const [min, max] = defaultPriceRange.value;
      priceRange.value = [min, max];
    } else {
      priceRange.value = [0, 0];
      priceRangeInitialised = false;
      pendingPriceRange = null;
    }
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

  if (key === "publicExploit") {
    showPublicExploitOnly.value = false;
    return;
  }

  if (key === "owned") {
    showOwnedOnly.value = false;
    return;
  }

  if (key === "marketProgramType") {
    selectedMarketProgramType.value = null;
    return;
  }

  filters[key] = null;
};

const truncateDescription = (value: string | null | undefined) => {
  if (!value) {
    return "No description provided.";
  }

  const trimmed = value.trim();

  if (trimmed.length <= 120) {
    return trimmed;
  }

  return `${trimmed.slice(0, 120)}…`;
};

const getEntryTitle = (entry: KevEntrySummary) =>
  entry.vulnerabilityName?.trim() || entry.cveId;

const columns = computed<TableColumn<KevEntrySummary>[]>(() => {
  if (showCompactTable.value) {
    return [
      {
        id: "title",
        header: "Title",
        cell: ({ row }) =>
          h(
            "p",
            {
              class:
                "max-w-xs break-words text-wrap text-sm font-semibold text-neutral-900 dark:text-neutral-50",
            },
            getEntryTitle(row.original),
          ),
      },
      {
        id: "description",
        header: "Description",
        cell: ({ row }) =>
          h(
            "p",
            {
              class:
                "max-w-xs break-words text-wrap text-sm",
            },
           truncateDescription(row.original.description),
          ),
      },
      {
        id: "vendor",
        header: "Vendor",
        cell: ({ row }) => row.original.vendor,
      },
      {
        id: "product",
        header: "Product",
        cell: ({ row }) => row.original.product,
      },
    ];
  }

  const createBadgeButton = (
    label: string,
    color: string,
    onClick: () => void,
    options: { isActive?: boolean; ariaLabel?: string } = {}
  ) =>
    h(
      "button",
      {
        type: "button",
        class: [
          "group rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 transition",
          options.isActive
            ? "ring-1 ring-inset ring-primary-400 dark:ring-primary-500/50"
            : "",
        ]
          .filter(Boolean)
          .join(" "),
        onClick,
        "aria-label": options.ariaLabel ?? undefined,
        "aria-pressed":
          typeof options.isActive === "boolean" ? options.isActive : undefined,
      },
      [
        h(
          UBadge,
          {
            color,
            variant: "soft",
            class:
              "pointer-events-none text-xs font-semibold transition-colors group-hover:bg-primary-100/80 group-hover:text-primary-700 dark:group-hover:bg-primary-500/15 dark:group-hover:text-primary-200",
          },
          () => label
        ),
      ]
    );

  return [
    {
      id: "summary",
      header: "Description",
      cell: ({ row }) => {
        const description =
          row.original.description || "No description provided.";
        const wellKnownLabel = getWellKnownCveName(row.original.cveId);
        const badgeRowChildren: Array<ReturnType<typeof h>> = [];

        const entry = row.original;
        const isTracked =
          trackedProductsReady.value &&
          trackedProductSet.value.has(entry.productKey);
        const hasServerSideRce = entry.exploitLayers.some((layer) =>
          layer.startsWith("RCE · Server-side")
        );
        const hasTrivialServerSide = entry.exploitLayers.includes(
          "RCE · Server-side Non-memory"
        );

        for (const source of row.original.sources) {
          const meta = sourceBadgeMap[source];
          const label = meta?.label ?? source.toUpperCase();
          const color = meta?.color ?? "neutral";
          badgeRowChildren.push(
            createBadgeButton(label, color, () => applyQuickFilters({ source }), {
              ariaLabel: `Filter catalog by ${label} source`,
              isActive: selectedSource.value === source,
            })
          );
        }

        if (entry.vendorKey && entry.vendor) {
          badgeRowChildren.push(
            createBadgeButton(
              entry.vendor,
              "primary",
              () =>
                applyQuickFilters({
                  filters: { vendor: entry.vendorKey },
                }),
              {
                ariaLabel: `Filter by vendor ${entry.vendor}`,
                isActive: filters.vendor === entry.vendorKey,
              }
            )
          );
        }

        if (entry.productKey && entry.product) {
          badgeRowChildren.push(
            createBadgeButton(
              entry.product,
              "secondary",
              () =>
                applyQuickFilters({
                  filters: { product: entry.productKey },
                }),
              {
                ariaLabel: `Filter by product ${entry.product}`,
                isActive: filters.product === entry.productKey,
              }
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
                "max-w-2xl whitespace-normal break-words font-medium text-neutral-900 dark:text-neutral-100",
            },
            row.original.vulnerabilityName
          ),
        ];

        if (badgeRowChildren.length) {
          children.push(
            h(
              "div",
              {
                class:
                  "flex flex-wrap items-center gap-2 text-neutral-500 dark:text-neutral-400",
              },
              badgeRowChildren
            )
          );
        }

        children.push(
          h(
            "p",
            {
              class:
                "text-sm text-neutral-500 dark:text-neutral-400 max-w-3xl whitespace-normal break-words text-pretty leading-relaxed",
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
        if (Number.isNaN(parsed.getTime())) {
          return row.original.dateAdded;
        }

        const absoluteLabel = formatDate(parsed, {
          fallback: row.original.dateAdded,
          preserveInputOnError: true,
        });
        const relativeLabel = formatRelativeDate(parsed, {
          fallback: absoluteLabel,
          maxUnits: 2,
        });
        const displayLabel = showRelativeDates.value
          ? relativeLabel
          : absoluteLabel;
        const alternateLabel = showRelativeDates.value
          ? absoluteLabel
          : relativeLabel;
        const titleLabel =
          alternateLabel && alternateLabel !== displayLabel
            ? alternateLabel
            : undefined;
        const year = parsed.getFullYear();
        const isActive =
          yearRange.value[0] === year && yearRange.value[1] === year;
        const ariaLabel = showRelativeDates.value
          ? `Filter catalog by year ${year}. Added ${absoluteLabel}.`
          : `Filter catalog by year ${year}`;

        return h(
          "button",
          {
            type: "button",
            class: [
              "rounded-md px-2 py-1 text-sm font-medium text-primary-600 transition hover:text-primary-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 dark:text-primary-300 dark:hover:text-primary-200",
              isActive ? "bg-primary-50/70 dark:bg-primary-500/10" : "",
            ]
              .filter(Boolean)
              .join(" "),
            onClick: () => applyQuickFilters({ year }),
            title: titleLabel,
            "aria-label": ariaLabel,
            "aria-pressed": isActive,
          },
          displayLabel
        );
      },
    },
    {
      id: "risk",
      header: "CVSS · EPSS",
      cell: ({ row }) => {
        const { cvssScore, cvssSeverity, epssScore } = row.original;
        const formattedCvss = formatCvssScore(cvssScore);
        const cvssLabel =
          formattedCvss || cvssSeverity
            ? buildCvssLabel(cvssSeverity, cvssScore)
            : null;
        const cvssColor = cvssSeverity
          ? cvssSeverityColors[cvssSeverity] ?? "neutral"
          : "neutral";
        const epssLabel = formatEpssScore(epssScore);

        const cvssNode = cvssLabel
          ? h(
              UBadge,
              {
                color: cvssColor,
                variant: "soft",
                class: "font-semibold",
              },
              () => cvssLabel
            )
          : h(
              "span",
              { class: "text-sm text-neutral-400 dark:text-neutral-500" },
              "—"
            );

        const epssNode = epssLabel
          ? h(
              UBadge,
              {
                color: "success",
                variant: "soft",
                class: "font-semibold",
              },
              () => `${epssLabel}%`
            )
          : h(
              "span",
              { class: "text-sm text-neutral-400 dark:text-neutral-500" },
              "—"
            );

        return h("div", { class: "flex flex-col gap-1" }, [cvssNode, epssNode]);
      },
    },
    {
      id: "taxonomy",
      header: "Domain · Exploit · Type",
      cell: ({ row }) => {
        const sections: Array<{
          title: string;
          values: string[];
          color: string;
          filterKey: "domain" | "exploit" | "vulnerability";
        }> = [
          {
            title: "Domain",
            values: row.original.domainCategories,
            color: "primary",
            filterKey: "domain",
          },
          {
            title: "Exploit profile",
            values: row.original.exploitLayers,
            color: "warning",
            filterKey: "exploit",
          },
          {
            title: "Type",
            values: row.original.vulnerabilityCategories,
            color: "secondary",
            filterKey: "vulnerability",
          },
        ];

        const sectionNodes = sections
          .filter((section) => section.values.length)
          .map((section) =>
            h("div", { class: "flex flex-col gap-1" }, [
              h(
                "div",
                { class: "flex flex-wrap gap-2" },
                section.values.map((value) => {
                  const isActive = filters[section.filterKey] === value;
                  const filterPayload: Partial<Record<FilterKey, string>> = {
                    [section.filterKey]: value,
                  };

                  return createBadgeButton(
                    value,
                    section.color,
                    () => applyQuickFilters({ filters: filterPayload }),
                    {
                      ariaLabel: `Filter by ${section.title.toLowerCase()} ${value}`,
                      isActive,
                    }
                  );
                })
              ),
            ])
          );

        if (!sectionNodes.length) {
          return h(
            "span",
            { class: "text-sm text-neutral-400 dark:text-neutral-500" },
            "—"
          );
        }

        return h("div", { class: "flex flex-col gap-3" }, sectionNodes);
      },
    },
  ];
});

const tableMeta = {
  class: {
    tr: "cursor-pointer transition-colors hover:bg-neutral-100/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500/60 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:hover:bg-neutral-800/60 dark:focus-visible:ring-offset-neutral-900",
  },
};
</script>

<template>
  <div class="grid grid-cols-12">
    <div v-if="showFilterPanel" class="col-span-3 ml-8 mt-36">
      <UCard>
        <template #header>
          <span class="text-xl font-bold text-neutral-900 dark:text-neutral-50">
            Filters
          </span>
        </template>

        <div class="space-y-6">
          <div
            v-if="canShowAllResults"
            class="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-300"
          >
            <span class="font-medium">Show all results</span>
            <USwitch
              v-model="showAllResults"
              aria-label="Toggle show all results"
            />
          </div>

          <UAccordion
            v-model="asideAccordionValue"
            type="multiple"
            :items="asideAccordionItems"
            class="w-full"
          >
            <template #default="{ item }">
              <div class="flex items-center justify-between gap-3">
                <span
                  class="text-sm font-semibold text-neutral-900 dark:text-neutral-100"
                >
                  {{ item.label }}
                </span>
                <UBadge
                  v-if="item.badgeText"
                  :color="item.badgeColor ?? 'neutral'"
                  variant="soft"
                  class="font-semibold"
                >
                  {{ item.badgeText }}
                </UBadge>
              </div>
            </template>

        <template #presets>
          <div class="space-y-6 px-2 py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Jump to curated combinations of catalog filters.
            </p>
            <div class="grid grid-cols-1 gap-3">
              <UButton
                v-for="preset in filterPresets"
                :key="preset.id"
                type="button"
                color="neutral"
                variant="ghost"
                size="md"
                :class="[
                  'group !flex items-start !gap-3 !rounded-xl border !px-3 !py-3 text-left transition focus:outline-none !focus-visible:ring-2 !focus-visible:ring-primary-500 !focus-visible:ring-offset-0',
                  isFilterPresetActive(preset.id)
                    ? 'border-primary-300 !bg-primary-50/70 dark:border-primary-500/60 dark:!bg-primary-500/10'
                    : 'border-neutral-200 !bg-white hover:border-primary-200 hover:!bg-primary-50/60 dark:border-neutral-800 dark:!bg-neutral-900 dark:hover:border-primary-500/40 dark:hover:!bg-primary-500/10',
                ]"
                @click="handleApplyFilterPreset(preset)"
              >
                <div
                  :class="[
                    'flex size-9 items-center justify-center rounded-lg border text-lg transition',
                    isFilterPresetActive(preset.id)
                      ? 'border-primary-300 bg-primary-100 dark:border-primary-500/60 dark:bg-primary-500/10'
                      : 'border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900',
                  ]"
                >
                  <UIcon
                    :name="preset.icon"
                    class="size-5"
                    :class="presetIconClassMap[preset.color] ?? presetIconClassMap.neutral"
                  />
                </div>
                <div class="flex-1 space-y-1">
                  <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                    {{ preset.label }}
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ preset.description }}
                  </p>
                </div>
              </UButton>
            </div>
          </div>
        </template>

        <template #filters>
          <div class="space-y-6 px-2  py-4">
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

                <div class="grid grid-cols-1 gap-6">
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
                        v-for="option in ['all', 'kev', 'enisa', 'historic', 'metasploit', 'poc']"
                        :key="option"
                        size="sm"
                        :color="selectedSource === option ? 'primary' : 'neutral'"
                        :variant="selectedSource === option ? 'solid' : 'outline'"
                        @click="
                          selectSource(
                            option as 'all' | 'kev' | 'enisa' | 'historic' | 'metasploit' | 'poc',
                          )
                        "
                      >
                        {{ option === "all" ? "All sources" : catalogSourceLabels[option as CatalogSource] }}
                      </UButton>
                    </div>
                  </UFormField>

                  <UFormField label="Market programs">
                    <div class="space-y-2">
                      <div class="flex flex-wrap gap-2">
                        <UButton
                          size="sm"
                          :color="
                            selectedMarketProgramType === 'exploit-broker'
                              ? 'primary'
                              : 'neutral'
                          "
                          :variant="
                            selectedMarketProgramType === 'exploit-broker'
                              ? 'solid'
                              : 'outline'
                          "
                          :aria-pressed="selectedMarketProgramType === 'exploit-broker'"
                          @click="toggleMarketProgramTypeFilter('exploit-broker')"
                        >
                          <span class="flex items-center gap-2">
                            Exploit brokers
                            <UBadge
                              color="error"
                              variant="soft"
                              class="text-[10px] font-semibold"
                            >
                              Market
                            </UBadge>
                          </span>
                        </UButton>
                      </div>
                      <p class="text-xs text-neutral-500 dark:text-neutral-400">
                        Highlight CVEs with exploit broker payouts.
                      </p>
                    </div>
                  </UFormField>
                </div>

                <div class="grid grid-cols-1 gap-6">
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
                        Filter vulnerabilities by the year CISA added them to the
                        KEV catalog.
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
                        Common Vulnerability Scoring System (0–10) shows
                        vendor-assigned severity.
                      </p>
                      <p class="text-xs text-neutral-500 dark:text-neutral-400">
                        {{ cvssRange[0].toFixed(1) }} –
                        {{ cvssRange[1].toFixed(1) }}
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
                        Exploit Prediction Scoring System (0–100%) estimates
                        likelihood of exploitation.
                      </p>
                      <p class="text-xs text-neutral-500 dark:text-neutral-400">
                        {{ Math.round(epssRange[0]) }} –
                        {{ Math.round(epssRange[1]) }}
                      </p>
                    </div>
                  </UFormField>

                  <UFormField label="Reward range">
                    <div class="space-y-2">
                      <USlider
                        v-model="priceRange"
                        :min="defaultPriceRange[0]"
                        :max="defaultPriceRange[1]"
                        :step="1000"
                        :disabled="!priceSliderReady"
                        :min-steps-between-thumbs="1"
                        tooltip
                      />
                      <p class="text-xs text-neutral-500 dark:text-neutral-400">
                        Filter vulnerabilities by the highest published payout signal.
                      </p>
                      <p class="text-xs text-neutral-500 dark:text-neutral-400">
                        <span v-if="priceSliderReady">
                          {{ currencyFormatter.format(priceRange[0]) }} –
                          {{ currencyFormatter.format(priceRange[1]) }}
                        </span>
                        <span v-else>Reward data not available.</span>
                      </p>
                    </div>
                  </UFormField>
                </div>
              </div>
        </template>

        <template #market>
          <div class="space-y-4 px-2 py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Link exploited products to current exploit acquisition and bounty signals.
            </p>
            <div
              class="rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
            >
              <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                {{ marketOfferCount.toLocaleString() }} mapped offers
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                {{ filteredMarketPriceSummary }}
              </p>
            </div>

            <div v-if="marketProgramCounts.length" class="space-y-2">
              <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Program types
              </p>
              <div class="flex flex-wrap gap-2">
                <UBadge
                  v-for="program in marketProgramCounts.slice(0, 3)"
                  :key="program.key"
                  color="info"
                  variant="soft"
                  class="text-xs font-semibold"
                >
                  {{ program.name }} · {{ program.count.toLocaleString() }}
                </UBadge>
              </div>
            </div>

            <div v-if="marketCategoryCounts.length" class="space-y-2">
              <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Leading categories
              </p>
              <div class="flex flex-wrap gap-2">
                <UBadge
                  v-for="category in marketCategoryCounts.slice(0, 4)"
                  :key="`${category.categoryType}-${category.key}`"
                  color="neutral"
                  variant="soft"
                  class="text-xs"
                >
                  {{ category.name }} · {{ category.count.toLocaleString() }}
                </UBadge>
              </div>
            </div>

            <ULink
              to="/market-intel"
              class="text-sm font-medium text-primary-600 transition hover:text-primary-500 dark:text-primary-300"
            >
              View market intelligence →
            </ULink>
          </div>
        </template>

        <template #sort>
          <div class="space-y-4 px-2">
            <UFormField label="Sort by">
              <USelectMenu
                v-model="sortOption"
                :items="sortOptionItems"
                value-key="value"
                size="sm"
              />
            </UFormField>

            <UFormField label="Order">
              <USelectMenu
                v-model="sortDirection"
                :items="sortDirectionItems"
                value-key="value"
                size="sm"
              />
            </UFormField>
          </div>
        </template>

        <template #domain>
          <div class="space-y-4 px-2  py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Share of vulnerabilities per domain grouping.
            </p>

            <div v-if="domainStats.length" class="space-y-3">
              <UButton
                v-for="stat in domainStats"
                :key="stat.key"
                type="button"
                color="neutral"
                variant="ghost"
                size="md"
                @click="toggleFilter('domain', stat.key)"
                :aria-pressed="filters.domain === stat.key"
                :class="[
                  'w-full cursor-pointer !flex !flex-col !items-stretch !gap-0 space-y-2 rounded-lg !px-3 !py-2 text-left ring-1 ring-transparent transition focus:outline-none !focus-visible:ring-2 !focus-visible:ring-emerald-400 dark:!focus-visible:ring-emerald-600',
                  filters.domain === stat.key
                    ? '!bg-emerald-50 dark:!bg-emerald-500/10 !ring-emerald-200 dark:!ring-emerald-500/40'
                    : '!bg-transparent hover:!bg-neutral-50 dark:hover:!bg-neutral-800/60',
                ]"
              >
                <div class="flex items-center justify-between gap-3 text-sm">
                  <span
                    :class="[
                      'truncate font-medium',
                      filters.domain === stat.key
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-neutral-900 dark:text-neutral-50',
                    ]"
                  >
                    {{ stat.name }}
                  </span>
                  <span
                    class="whitespace-nowrap text-xs text-neutral-500 dark:text-neutral-400"
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
              </UButton>
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

            <div
              v-if="domainMissingCategories.length"
              :class="missingFilterSectionClass"
            >
              <p
                class="text-[10px] font-semibold uppercase tracking-wide text-neutral-400 dark:text-neutral-500"
              >
                No matches yet
              </p>
              <div class="flex flex-wrap gap-1.5">
                <span
                  v-for="category in domainMissingCategories"
                  :key="`missing-domain-${category}`"
                  :class="missingFilterPillClass"
                >
                  {{ category }}
                </span>
              </div>
            </div>
          </div>
        </template>

        <template #exploit>
          <div class="space-y-4  px-2  py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              How execution paths cluster for these CVEs.
            </p>

            <div v-if="exploitLayerStats.length" class="space-y-3">
              <UButton
                v-for="stat in exploitLayerStats"
                :key="stat.key"
                type="button"
                color="neutral"
                variant="ghost"
                size="md"
                @click="toggleFilter('exploit', stat.key)"
                :aria-pressed="filters.exploit === stat.key"
                :class="[
                  'w-full cursor-pointer !flex !flex-col !items-stretch !gap-0 space-y-2 rounded-lg !px-3 !py-2 text-left ring-1 ring-transparent transition focus:outline-none !focus-visible:ring-2 !focus-visible:ring-amber-400 dark:!focus-visible:ring-amber-600',
                  filters.exploit === stat.key
                    ? '!bg-amber-50 dark:!bg-amber-500/10 !ring-amber-200 dark:!ring-amber-500/40'
                    : '!bg-transparent hover:!bg-neutral-50 dark:hover:!bg-neutral-800/60',
                ]"
              >
                <div class="flex items-center justify-between gap-3 text-sm">
                  <span
                    :class="[
                      'truncate font-medium',
                      filters.exploit === stat.key
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-neutral-900 dark:text-neutral-50',
                    ]"
                  >
                    {{ stat.name }}
                  </span>
                  <span
                    class="whitespace-nowrap text-xs text-neutral-500 dark:text-neutral-400"
                  >
                    {{ stat.count }} · {{ stat.percentLabel }}%
                  </span>
                </div>
                <UProgress
                  :model-value="stat.percent"
                  :max="100"
                  color="warning"
                  size="sm"
                />
              </UButton>
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
                {{ topExploitLayerStat.name }} ({{
                  topExploitLayerStat.percentLabel
                }}%)
              </span>
            </div>

            <div
              v-if="exploitMissingCategories.length"
              :class="missingFilterSectionClass"
            >
              <p
                class="text-[10px] font-semibold uppercase tracking-wide text-neutral-400 dark:text-neutral-500"
              >
                No matches yet
              </p>
              <div class="flex flex-wrap gap-1.5">
                <span
                  v-for="category in exploitMissingCategories"
                  :key="`missing-exploit-${category}`"
                  :class="missingFilterPillClass"
                >
                  {{ category }}
                </span>
              </div>
            </div>
          </div>
        </template>

        <template #vulnerability>
          <div class="space-y-4  px-2  py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Breakdown of vulnerability categories across matching exploits.
            </p>

            <div v-if="vulnerabilityStats.length" class="space-y-3">
              <UButton
                v-for="stat in vulnerabilityStats"
                :key="stat.key"
                type="button"
                color="neutral"
                variant="ghost"
                size="md"
                @click="toggleFilter('vulnerability', stat.key)"
                :aria-pressed="filters.vulnerability === stat.key"
                :class="[
                  'w-full cursor-pointer !flex !flex-col !items-stretch !gap-0 space-y-2 rounded-lg !px-3 !py-2 text-left ring-1 ring-transparent transition focus:outline-none !focus-visible:ring-2 !focus-visible:ring-rose-400 dark:!focus-visible:ring-rose-600',
                  filters.vulnerability === stat.key
                    ? '!bg-rose-50 dark:!bg-rose-500/10 !ring-rose-200 dark:!ring-rose-500/40'
                    : '!bg-transparent hover:!bg-neutral-50 dark:hover:!bg-neutral-800/60',
                ]"
              >
                <div class="flex items-center justify-between gap-3 text-sm">
                  <span
                    :class="[
                      'truncate font-medium',
                      filters.vulnerability === stat.key
                        ? 'text-rose-600 dark:text-rose-400'
                        : 'text-neutral-900 dark:text-neutral-50',
                    ]"
                  >
                    {{ stat.name }}
                  </span>
                  <span
                    class="whitespace-nowrap text-xs text-neutral-500 dark:text-neutral-400"
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
              </UButton>
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
                {{ topVulnerabilityStat.name }} ({{
                  topVulnerabilityStat.percentLabel
                }}%)
              </span>
            </div>

            <div
              v-if="vulnerabilityMissingCategories.length"
              :class="missingFilterSectionClass"
            >
              <p
                class="text-[10px] font-semibold uppercase tracking-wide text-neutral-400 dark:text-neutral-500"
              >
                No matches yet
              </p>
              <div class="flex flex-wrap gap-1.5">
                <span
                  v-for="category in vulnerabilityMissingCategories"
                  :key="`missing-vulnerability-${category}`"
                  :class="missingFilterPillClass"
                >
                  {{ category }}
                </span>
              </div>
            </div>
          </div>
        </template>

        <template #topVendors>
          <div class="space-y-4  px-2  py-4">
            <UFormField label="Show" class="w-32">
              <USelectMenu
                v-model="topVendorCount"
                :items="topCountItems"
                value-key="value"
                size="sm"
              />
            </UFormField>

            <div v-if="topVendorStats.length" class="space-y-3">
              <UButton
                v-for="stat in topVendorStats"
                :key="stat.key"
                type="button"
                color="neutral"
                variant="ghost"
                size="md"
                @click="toggleFilter('vendor', stat.key)"
                :aria-pressed="filters.vendor === stat.key"
                :class="[
                  'w-full cursor-pointer !flex !flex-col !items-stretch !gap-0 space-y-2 rounded-lg !px-3 !py-2 text-left ring-1 ring-transparent transition focus:outline-none !focus-visible:ring-2 !focus-visible:ring-primary-400 dark:!focus-visible:ring-primary-600',
                  filters.vendor === stat.key
                    ? '!bg-primary-50 dark:!bg-primary-500/10 !ring-primary-200 dark:!ring-primary-500/40'
                    : '!bg-transparent hover:!bg-neutral-50 dark:hover:!bg-neutral-800/60',
                ]"
              >
                <div class="flex items-center justify-between gap-3 text-sm">
                  <span
                    :class="[
                      'truncate font-medium',
                      filters.vendor === stat.key
                        ? 'text-primary-600 dark:text-primary-400'
                        : 'text-neutral-900 dark:text-neutral-50',
                    ]"
                  >
                    {{ stat.name }}
                  </span>
                  <span
                    class="whitespace-nowrap text-xs text-neutral-500 dark:text-neutral-400"
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
              </UButton>
            </div>
            <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
              No vendor data for this filter.
            </p>
          </div>
        </template>

        <template #topProducts>
          <div class="space-y-4  px-2  py-4">
            <UFormField label="Show" class="w-32">
              <USelectMenu
                v-model="topProductCount"
                :items="topCountItems"
                value-key="value"
                size="sm"
              />
            </UFormField>

            <div v-if="topProductStats.length" class="space-y-3">
              <UButton
                v-for="stat in topProductStats"
                :key="stat.key"
                type="button"
                color="neutral"
                variant="ghost"
                size="md"
                @click="toggleFilter('product', stat.key)"
                :aria-pressed="filters.product === stat.key"
                :class="[
                  'w-full cursor-pointer !flex !flex-col !items-stretch !gap-0 space-y-2 rounded-lg !px-3 !py-2 text-left ring-1 ring-transparent transition focus:outline-none !focus-visible:ring-2 !focus-visible:ring-secondary-400 dark:!focus-visible:ring-secondary-600',
                  filters.product === stat.key
                    ? '!bg-secondary-50 dark:!bg-secondary-500/10 !ring-secondary-200 dark:!ring-secondary-500/40'
                    : '!bg-transparent hover:!bg-neutral-50 dark:hover:!bg-neutral-800/60',
                ]"
              >
                <div class="flex items-center justify-between gap-3 text-sm">
                  <div class="min-w-0">
                    <p
                      :class="[
                        'truncate font-medium',
                        filters.product === stat.key
                          ? 'text-secondary-600 dark:text-secondary-400'
                          : 'text-neutral-900 dark:text-neutral-50',
                      ]"
                    >
                      {{ stat.name }}
                    </p>
                    <p
                      v-if="stat.vendorName"
                      class="truncate text-xs text-neutral-500 dark:text-neutral-400"
                    >
                      {{ stat.vendorName }}
                    </p>
                  </div>
                  <span
                    class="whitespace-nowrap text-xs text-neutral-500 dark:text-neutral-400"
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
              </UButton>
            </div>
            <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
              No product data for this filter.
            </p>
          </div>
        </template>

        <template #focus>
          <div class="space-y-4  py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Highlight the vulnerabilities that matter most to your
              organisation.
            </p>

            <div class="space-y-3">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    My software
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Only show CVEs that match the products you track.
                  </p>
                </div>
                <USwitch
                  v-model="showOwnedOnly"
                  :disabled="!trackedProductsReady"
                />
              </div>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Named CVEs
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Elevate high-profile, widely reported vulnerabilities.
                  </p>
                </div>
                <USwitch v-model="showWellKnownOnly" />
              </div>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Ransomware focus
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Restrict the view to CVEs linked to ransomware campaigns.
                  </p>
                </div>
                <USwitch v-model="showRansomwareOnly" />
              </div>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Public exploit coverage
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Surface CVEs with Metasploit modules or published GitHub PoCs.
                  </p>
                </div>
                <USwitch v-model="showPublicExploitOnly" />
              </div>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Internet exposure
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Prioritise vulnerabilities likely to be exposed on the open
                    internet.
                  </p>
                </div>
                <USwitch v-model="showInternetExposedOnly" />
              </div>
            </div>

            <div
              class="rounded-lg border border-neutral-200 bg-neutral-50/70 p-4 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/40 dark:text-neutral-300"
            >
              <p class="font-semibold text-neutral-700 dark:text-neutral-100">
                Tracked products
              </p>
              <p class="mt-1">
                {{ trackedProductCount.toLocaleString() }} product(s) selected.
              </p>
              <p class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                Manage the list on the dashboard at any time; changes are saved
                automatically.
              </p>
            </div>
          </div>
        </template>

        <template #mySoftware>
          <div class="space-y-4 py-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Review coverage and exploit activity for the software you track
              without leaving the table.
            </p>

            <div
              role="button"
              tabindex="0"
              :aria-label="`View tracked CVEs from the last ${trackedProductSummary.recentWindowLabel}`"
              class="group rounded-lg border border-neutral-200 bg-neutral-50/70 p-4 text-sm text-neutral-600 transition hover:border-primary-300/70 hover:bg-primary-50/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-400 dark:border-neutral-800 dark:bg-neutral-900/40 dark:text-neutral-300 dark:hover:border-primary-400/40 dark:hover:bg-primary-500/10"
              @click="handleTrackedSummaryQuickFilter"
              @keydown.enter.prevent.stop="handleTrackedSummaryQuickFilter"
              @keydown.space.prevent.stop="handleTrackedSummaryQuickFilter"
            >
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p class="font-semibold text-neutral-700 dark:text-neutral-100">
                    {{ trackedProductCount.toLocaleString() }} tracked product{{
                      trackedProductCount === 1 ? '' : 's'
                    }}
                  </p>
                  <p class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                    {{ trackedProductSummary.recentCount.toLocaleString() }} new ·
                    {{ trackedProductSummary.recentWindowLabel }}
                  </p>
                </div>
                <UBadge color="primary" variant="soft" class="font-semibold">
                  {{ trackedProductSummary.totalCount.toLocaleString() }} total CVEs
                </UBadge>
              </div>
              <p class="mt-3 text-xs text-neutral-500 transition group-hover:text-primary-700 dark:text-neutral-400 dark:group-hover:text-primary-300">
                Click to focus the catalog on your tracked software, or open the
                panel to manage the list and explore severity details.
              </p>
            </div>

            <UButton
              color="neutral"
              variant="soft"
              icon="i-lucide-layers"
              @click="showMySoftwareSlideover = true"
            >
              Open my software panel
            </UButton>
          </div>
        </template>

        <template #trend>
          <div class="space-y-4">
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Examine how the current filters influence volume, severity, and
              exploitation momentum over time.
            </p>

            <div class="space-y-3">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Show risk details
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Add severity and EPSS context to the explorer insights.
                  </p>
                </div>
                <USwitch v-model="showRiskDetails" />
              </div>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Show trend lines
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Overlay trend lines on charts when exploring results.
                  </p>
                </div>
                <USwitch v-model="showTrendLines" />
              </div>
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p
                    class="text-sm font-medium text-neutral-700 dark:text-neutral-200"
                  >
                    Show relative dates
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Display catalog dates as durations (for example, 4mo 3d ago).
                  </p>
                </div>
                <USwitch v-model="showRelativeDates" />
              </div>
            </div>

            <UButton
              color="neutral"
              variant="soft"
              icon="i-lucide-line-chart"
              @click="showTrendSlideover = true"
            >
              Launch trend explorer
            </UButton>
          </div>
        </template>
      </UAccordion>
        </div>
      </UCard>
    </div>

    <div
      :class="[
        showFilterPanel ? 'col-span-9' : 'col-span-12',
        'mx-auto w-full px-12',
      ]"
    >
      <div
        class="sticky top-24 z-50 flex w-full"
        :class="showFilterPanel ? 'justify-center' : 'justify-start'"
      >
        <QuickFilterSummary
          :quick-stat-items="quickStatItems"
          :active-filters="activeFilters"
          :has-active-filters="hasActiveFilters"
          :has-active-filter-chips="hasActiveFilterChips"
          :show-filter-chips="showQuickFilterChips"
          :show-reset-button="showQuickFilterResetButton"
          :year-range="yearRange"
          :year-bounds="yearBounds"
          :has-custom-year-range="hasCustomYearRange"
          :is-year-range-limited="isYearRangeLimited"
          :search-input="searchInput"
          search-placeholder="Filter catalog"
          @reset="resetFilters"
          @clear-filter="clearFilter"
          @update:year-range="handleQuickYearRangeUpdate"
          @reset-year-range="resetYearRange"
          @clear-year-range="clearYearRange"
          @update:search-input="handleQuickSearchUpdate"
        />
      </div>

      <UCard class="mt-24">
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="space-y-1">
              <p class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                Catalog results
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Explore the filtered entries and launch the classification audit when you spot anomalies.
              </p>
            </div>
            <div class="flex flex-wrap items-center justify-end gap-3">
              <UButton
                color="neutral"
                variant="ghost"
                size="sm"
                class="whitespace-nowrap"
                :icon="filterPanelToggleIcon"
                :aria-pressed="!showFilterPanel"
                :aria-label="filterPanelToggleAriaLabel"
                @click="showFilterPanel = !showFilterPanel"
              >
                {{ filterPanelToggleLabel }}
              </UButton>
              <div class="flex items-center gap-2">
                <USwitch
                  v-model="showCompactTable"
                  :disabled="isBusy || !results.length"
                  aria-label="Toggle summary view for catalog table"
                />
                <div class="flex flex-col text-right leading-tight">
                  <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
                    Summary view
                  </span>
                  <span class="text-xs text-neutral-500 dark:text-neutral-400">
                    Dense
                  </span>
                </div>
              </div>
              <div class="flex items-center gap-2">
                <USwitch
                  v-model="showHeatmap"
                  :disabled="isBusy || !results.length"
                  aria-label="Toggle heatmap view for catalog results"
                />
                <div class="flex flex-col text-right leading-tight">
                  <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
                    Heatmap view
                  </span>
                  <span class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ showHeatmap ? 'Vendor & product spotlight' : 'Tabular breakdown' }}
                  </span>
                </div>
              </div>
              <!-- <UButton
                color="neutral"
                variant="outline"
                icon="i-lucide-sparkles"
                :disabled="isBusy || !results.length"
                @click="showClassificationReviewSlideover = true"
              >
                LLM classification audit
              </UButton> -->
            </div>
          </div>
        </template>
        <div>
          <UProgress
            v-if="isBusy"
            class="mb-4"
            animation="swing"
            color="primary"
          />
          <div
            v-if="showCatalogEmptyState"
            class="rounded-lg border border-dashed border-neutral-200 bg-neutral-50 px-6 py-10 text-center text-sm text-neutral-500 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-400"
          >
            {{ catalogEmptyMessage }}
          </div>
          <div v-else>
            <CatalogHeatmapView
              v-if="showHeatmap"
              :entries="results"
              @quick-filter="handleCatalogHeatmapQuickFilter"
            />
            <UTable
              v-else
              ref="table"
              v-model:pagination="pagination"
              :data="results"
              :columns="columns"
              :meta="tableMeta"
              :pagination-options="{
                getPaginationRowModel: getPaginationRowModel()
              }"
              @select="handleTableSelect"
            />

            <div
              v-if="results.length"
              class="mt-4 flex flex-col items-center gap-2 border-t border-default pt-4 text-xs text-neutral-500 dark:text-neutral-400"
            >
              <span>{{ resultCountLabel }}</span>
              <UPagination
                v-if="
                  results.length > pagination.pageSize ||
                  (table?.tableApi?.getPageCount?.() ?? 0) > 1
                "
                :default-page="
                  (table?.tableApi?.getState().pagination.pageIndex ?? pagination.pageIndex) + 1
                "
                :items-per-page="
                  table?.tableApi?.getState().pagination.pageSize ?? pagination.pageSize
                "
                :total="
                  table?.tableApi?.getFilteredRowModel().rows.length || results.length
                "
                @update:page="handlePageUpdate"
              />
            </div>
          </div>
        </div>
      </UCard>

      <CatalogDetailModal
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
        @quick-filter="handleDetailQuickFilter"
      />
      <TrendExplorerSlideover
        v-model:open="showTrendSlideover"
        v-model:show-risk-details="showRiskDetails"
        v-model:show-trend-lines="showTrendLines"
        v-model:show-heatmap="showHeatmap"
        v-model:latest-addition-sort-key="latestAdditionSortKey"
        :is-busy="isBusy"
        :matching-results-label="matchingResultsLabel"
        :period-label="periodLabel"
        :high-severity-share-label="highSeverityShareLabel"
        :high-severity-summary="highSeveritySummary"
        :high-severity-trend="highSeverityTrend"
        :average-cvss-label="averageCvssLabel"
        :average-cvss-summary="averageCvssSummary"
        :average-cvss-trend="averageCvssTrend"
        :ransomware-share-label="ransomwareShareLabel"
        :ransomware-summary="ransomwareSummary"
        :ransomware-trend="ransomwareTrend"
        :internet-exposed-share-label="internetExposedShareLabel"
        :internet-exposed-summary="internetExposedSummary"
        :internet-exposed-trend="internetExposedTrend"
        :severity-distribution="severityDistribution"
        :latest-addition-summaries="latestAdditionSummaries"
        :latest-addition-notes="latestAdditionNotes"
        :latest-addition-sort-options="latestAdditionSortOptions"
        :tracked-products-ready="trackedProductsReady"
        :source-badge-map="sourceBadgeMap"
        :catalog-updated-at="catalogUpdatedAt"
        :entries="results"
        :focus-context="riskFocusContext"
        @open-details="openDetails"
        @add-to-tracked="handleAddToTracked"
        @quick-filter="handleTrendQuickFilter"
      />
      <MySoftwareSlideover
        v-model:open="showMySoftwareSlideover"
        v-model:show-owned-only="showOwnedOnly"
        :tracked-products-ready="trackedProductsReady"
        :tracked-products="trackedProducts"
        :tracked-product-count="trackedProductCount"
        :has-tracked-products="hasTrackedProducts"
        :saving="savingTrackedProducts"
        :save-error="trackedProductError"
        :product-insights="trackedProductInsights"
        :summary="trackedProductSummary"
        :recent-window-days="trackedRecentWindowDays"
        @remove="removeTrackedProduct"
        @clear="clearTrackedProducts"
        @quick-filter="handleTrackedInsightQuickFilter"
        @quick-filter-summary="handleTrackedSummaryQuickFilter"
      />
      <ClassificationReviewSlideover
        v-model:open="showClassificationReviewSlideover"
        :entries="results"
        :matching-results-label="matchingResultsLabel"
        :active-filters="activeFilters"
        :has-active-filters="hasActiveFilters"
        :is-busy="isBusy"
      />
    </div>
  </div>
</template>
