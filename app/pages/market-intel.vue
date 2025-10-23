<script setup lang="ts">
import { useDebounceFn } from "@vueuse/core";
import { computed, h, ref, watch } from "vue";
import type { TableColumn, TableRow } from "@nuxt/ui";
import MarketOfferDetailModal from "~/components/MarketOfferDetailModal.vue";
import StatCard from "~/components/StatCard.vue";
import { useDateDisplay } from "~/composables/useDateDisplay";
import type {
  MarketOfferListItem,
  MarketOffersResponse,
  MarketProgramType,
  MarketStatsResponse,
} from "~/types";

const { formatDate } = useDateDisplay();

const currencyFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  maximumFractionDigits: 0,
});

const formatProgramTypeLabel = (type: MarketProgramType) => {
  if (type === "exploit-broker") {
    return "Exploit brokers";
  }
  if (type === "bug-bounty") {
    return "Bug bounty";
  }
  if (type === "other") {
    return "Other programs";
  }
  return type;
};

const formatRewardRange = (offer: MarketOfferListItem) => {
  const { minRewardUsd, maxRewardUsd } = offer;

  if (typeof minRewardUsd === "number" && typeof maxRewardUsd === "number") {
    return `${currencyFormatter.format(minRewardUsd)} – ${currencyFormatter.format(maxRewardUsd)}`;
  }

  if (typeof minRewardUsd === "number") {
    return currencyFormatter.format(minRewardUsd);
  }

  if (typeof maxRewardUsd === "number") {
    return currencyFormatter.format(maxRewardUsd);
  }

  return "Not published";
};

const formatCategoryTypeLabel = (value: string) =>
  value
    .split(/[-_\s]+/u)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const { data, pending, error } = await useFetch<MarketStatsResponse>(
  "/api/market/stats",
  {
    headers: {
      "cache-control": "no-store",
    },
    default: () => ({
      totals: {
        offerCount: 0,
        programCount: 0,
        averageRewardUsd: null,
        minRewardUsd: null,
        maxRewardUsd: null,
        lastSeenAt: null,
      },
      programCounts: [],
      categoryCounts: [],
      topOffers: [],
    }),
  },
);

const totals = computed(() => data.value?.totals);
const programCounts = computed(() => data.value?.programCounts ?? []);
const categoryCounts = computed(() => data.value?.categoryCounts ?? []);
const topOffers = computed(() => data.value?.topOffers ?? []);

const isLoading = computed(() => pending.value);

const offerCountLabel = computed(() =>
  totals.value ? totals.value.offerCount.toLocaleString() : "0",
);

const programCountLabel = computed(() =>
  totals.value ? totals.value.programCount.toLocaleString() : "0",
);

const averageRewardLabel = computed(() => {
  const value = totals.value?.averageRewardUsd;
  return typeof value === "number" ? currencyFormatter.format(value) : "Not available";
});

const lastCaptureLabel = computed(() => {
  const timestamp = totals.value?.lastSeenAt;
  return timestamp
    ? formatDate(timestamp, { fallback: timestamp, preserveInputOnError: true })
    : "Not available";
});

const route = useRoute();
const router = useRouter();

type MarketOfferSortKey =
  | "sourceCaptureDate"
  | "maxRewardUsd"
  | "minRewardUsd"
  | "averageRewardUsd"
  | "title"
  | "programName";

const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;

const searchInput = ref("");
const searchTerm = ref("");
const selectedProgramTypes = ref<MarketProgramType[]>([]);
const hasKevOnly = ref(false);
const minReward = ref<number | null>(null);
const maxReward = ref<number | null>(null);
const minRewardInput = ref("");
const maxRewardInput = ref("");
const sortKey = ref<MarketOfferSortKey>("sourceCaptureDate");
const sortDirection = ref<"asc" | "desc">("desc");
const page = ref(1);
const pageSize = ref(DEFAULT_PAGE_SIZE);

const programTypeOptions: Array<{ label: string; value: MarketProgramType }> = [
  { label: "Exploit brokers", value: "exploit-broker" },
  { label: "Bug bounty", value: "bug-bounty" },
  { label: "Other programs", value: "other" },
];

const sortOptionItems = [
  { label: "Last captured", value: "sourceCaptureDate" },
  { label: "Maximum reward", value: "maxRewardUsd" },
  { label: "Minimum reward", value: "minRewardUsd" },
  { label: "Average reward", value: "averageRewardUsd" },
  { label: "Program", value: "programName" },
  { label: "Offer title", value: "title" },
];

const sortDirectionItems = [
  { label: "Descending", value: "desc" },
  { label: "Ascending", value: "asc" },
];

const parseBooleanParam = (value: string | null): boolean | null => {
  if (value === null) {
    return null;
  }
  const normalised = value.trim().toLowerCase();
  if (normalised === "true") {
    return true;
  }
  if (normalised === "false") {
    return false;
  }
  return null;
};

const parseNumberParam = (value: string | null): number | null => {
  if (value === null) {
    return null;
  }
  const parsed = Number.parseFloat(value.trim());
  if (Number.isNaN(parsed) || !Number.isFinite(parsed)) {
    return null;
  }
  return Math.max(0, Math.round(parsed));
};

const parseSortKey = (value: string | null): MarketOfferSortKey => {
  if (
    value === "maxRewardUsd" ||
    value === "minRewardUsd" ||
    value === "averageRewardUsd" ||
    value === "title" ||
    value === "programName" ||
    value === "sourceCaptureDate"
  ) {
    return value;
  }
  return "sourceCaptureDate";
};

const parseSortDirection = (value: string | null): "asc" | "desc" =>
  value === "asc" ? "asc" : "desc";

const getQueryValue = (value: unknown): string | null => {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    const first = value.find((entry): entry is string => typeof entry === "string");
    return first ?? null;
  }
  return null;
};

const toRouteQueryRecord = (query: Record<string, unknown>): Record<string, string> => {
  const record: Record<string, string> = {};
  for (const [key, value] of Object.entries(query)) {
    const parsed = getQueryValue(value);
    if (parsed) {
      record[key] = parsed;
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

const applyRouteQueryState = (query: Record<string, unknown>) => {
  const searchValue = getQueryValue(query.q);
  searchInput.value = searchValue?.trim() ?? "";
  searchTerm.value = searchValue?.trim() ?? "";

  const programParam = getQueryValue(query.programType);
  if (programParam) {
    const values = programParam
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    const mapped = values.map((value) =>
      value === "exploit-broker" || value === "bug-bounty" || value === "other"
        ? (value as MarketProgramType)
        : "other",
    );
    selectedProgramTypes.value = Array.from(new Set(mapped));
  } else {
    selectedProgramTypes.value = [];
  }

  const hasKevValue = parseBooleanParam(getQueryValue(query.hasKev));
  hasKevOnly.value = hasKevValue ?? false;

  const minValue = parseNumberParam(getQueryValue(query.minReward));
  const maxValue = parseNumberParam(getQueryValue(query.maxReward));

  if (minValue !== null && maxValue !== null && minValue > maxValue) {
    minReward.value = maxValue;
    maxReward.value = minValue;
    minRewardInput.value = String(maxValue);
    maxRewardInput.value = String(minValue);
  } else {
    minReward.value = minValue;
    maxReward.value = maxValue;
    minRewardInput.value = minValue !== null ? String(minValue) : "";
    maxRewardInput.value = maxValue !== null ? String(maxValue) : "";
  }

  sortKey.value = parseSortKey(getQueryValue(query.sort));
  sortDirection.value = parseSortDirection(getQueryValue(query.direction));

  const parsedPage = parseNumberParam(getQueryValue(query.page));
  page.value = parsedPage !== null && parsedPage > 0 ? parsedPage : 1;

  const parsedSize = parseNumberParam(getQueryValue(query.pageSize));
  const resolvedSize = parsedSize !== null && parsedSize > 0 ? parsedSize : DEFAULT_PAGE_SIZE;
  pageSize.value = Math.max(1, Math.min(resolvedSize, MAX_PAGE_SIZE));
};

let hasAppliedInitialRoute = false;
let isApplyingRouteState = false;
let isReplacingRouteQuery = false;

watch(
  () => route.query,
  (next) => {
    if (isReplacingRouteQuery) {
      return;
    }

    isApplyingRouteState = true;
    applyRouteQueryState(next as Record<string, unknown>);
    isApplyingRouteState = false;
    hasAppliedInitialRoute = true;
  },
  { immediate: true, deep: true },
);

const routeQueryState = computed<Record<string, string>>(() => {
  const query: Record<string, string> = {};

  const trimmedSearch = searchTerm.value.trim();
  if (trimmedSearch) {
    query.q = trimmedSearch;
  }

  if (selectedProgramTypes.value.length) {
    query.programType = selectedProgramTypes.value.join(",");
  }

  if (hasKevOnly.value) {
    query.hasKev = "true";
  }

  if (minReward.value !== null) {
    query.minReward = String(minReward.value);
  }

  if (maxReward.value !== null) {
    query.maxReward = String(maxReward.value);
  }

  if (sortKey.value !== "sourceCaptureDate") {
    query.sort = sortKey.value;
  }

  if (sortDirection.value !== "desc") {
    query.direction = sortDirection.value;
  }

  if (page.value > 1) {
    query.page = String(page.value);
  }

  if (pageSize.value !== DEFAULT_PAGE_SIZE) {
    query.pageSize = String(pageSize.value);
  }

  return query;
});

watch(
  routeQueryState,
  (next) => {
    if (!hasAppliedInitialRoute || isApplyingRouteState) {
      return;
    }

    const current = toRouteQueryRecord(route.query as Record<string, unknown>);
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

const updateSearch = useDebounceFn((value: string) => {
  const trimmed = value.trim();
  if (searchTerm.value !== trimmed) {
    searchTerm.value = trimmed;
  }
}, 500);

const parseRewardInput = (value: string): number | null => {
  if (!value.trim()) {
    return null;
  }
  const parsed = Number.parseFloat(value.trim());
  if (Number.isNaN(parsed) || !Number.isFinite(parsed)) {
    return null;
  }
  return Math.max(0, Math.round(parsed));
};

watch(
  searchInput,
  (value) => {
    if (isApplyingRouteState) {
      searchTerm.value = value.trim();
      return;
    }
    updateSearch(value);
  },
  { immediate: false },
);

watch(minRewardInput, (value) => {
  const parsed = parseRewardInput(value);
  if (minReward.value !== parsed) {
    minReward.value = parsed;
  }
});

watch(maxRewardInput, (value) => {
  const parsed = parseRewardInput(value);
  if (maxReward.value !== parsed) {
    maxReward.value = parsed;
  }
});

watch(
  [
    searchTerm,
    () => selectedProgramTypes.value.join("|"),
    hasKevOnly,
    minReward,
    maxReward,
    sortKey,
    sortDirection,
  ],
  () => {
    if (isApplyingRouteState) {
      return;
    }
    if (page.value !== 1) {
      page.value = 1;
    }
  },
);

const toggleProgramType = (value: MarketProgramType) => {
  const current = new Set(selectedProgramTypes.value);
  if (current.has(value)) {
    current.delete(value);
  } else {
    current.add(value);
  }
  selectedProgramTypes.value = Array.from(current);
};

const isProgramTypeSelected = (value: MarketProgramType) =>
  selectedProgramTypes.value.includes(value);

const clearFilters = () => {
  searchInput.value = "";
  searchTerm.value = "";
  selectedProgramTypes.value = [];
  hasKevOnly.value = false;
  minReward.value = null;
  maxReward.value = null;
  minRewardInput.value = "";
  maxRewardInput.value = "";
  page.value = 1;
};

const activeFilterCount = computed(() => {
  let count = 0;
  if (searchTerm.value.trim()) {
    count += 1;
  }
  if (selectedProgramTypes.value.length) {
    count += 1;
  }
  if (hasKevOnly.value) {
    count += 1;
  }
  if (minReward.value !== null || maxReward.value !== null) {
    count += 1;
  }
  return count;
});

const offerQueryParams = computed(() => {
  const params: Record<string, string> = {
    sort: sortKey.value,
    direction: sortDirection.value,
    page: String(page.value),
    pageSize: String(pageSize.value),
  };

  const trimmedSearch = searchTerm.value.trim();
  if (trimmedSearch) {
    params.q = trimmedSearch;
  }

  if (selectedProgramTypes.value.length) {
    params.programType = selectedProgramTypes.value.join(",");
  }

  if (hasKevOnly.value) {
    params.hasKev = "true";
  }

  if (minReward.value !== null) {
    params.minReward = String(minReward.value);
  }

  if (maxReward.value !== null) {
    params.maxReward = String(maxReward.value);
  }

  return params;
});

const {
  data: offersData,
  pending: offersPendingState,
  error: offersErrorState,
} = await useAsyncData(
  "market-offers",
  () =>
    $fetch<MarketOffersResponse>("/api/market/offers", {
      query: offerQueryParams.value,
    }),
  { watch: [offerQueryParams] },
);

watch(
  () => offersData.value?.page,
  (value) => {
    if (typeof value === "number" && value > 0 && page.value !== value) {
      page.value = value;
    }
  },
);

watch(
  () => offersData.value?.pageSize,
  (value) => {
    if (typeof value === "number" && value > 0 && pageSize.value !== value) {
      pageSize.value = Math.max(1, Math.min(value, MAX_PAGE_SIZE));
    }
  },
);

const offers = computed(() => offersData.value?.items ?? []);
const offersTotal = computed(() => offersData.value?.total ?? 0);
const offersPending = computed(() => offersPendingState.value);
const offersError = computed(() => offersErrorState.value);

const offersSummaryLabel = computed(() => {
  if (offersPending.value) {
    return "Loading offers…";
  }
  if (!offersTotal.value) {
    return "No offers to display";
  }
  const currentPage = Math.max(1, page.value);
  const start = (currentPage - 1) * pageSize.value + 1;
  const end = offers.value.length
    ? Math.min(start + offers.value.length - 1, offersTotal.value)
    : Math.min(start, offersTotal.value);
  return `${start.toLocaleString()} – ${end.toLocaleString()} of ${offersTotal.value.toLocaleString()} offers`;
});

const offersErrorMessage = computed(() => offersError.value?.message ?? "");

const showOfferModal = ref(false);
const selectedOffer = ref<MarketOfferListItem | null>(null);

const offerTableUi = {
  class: {
    th: "px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400",
    td: "align-top px-3 py-3 text-sm text-neutral-600 dark:text-neutral-300",
    tr: "cursor-pointer transition hover:bg-neutral-50 dark:hover:bg-neutral-800/60",
  },
};

const offerColumns = computed<TableColumn<MarketOfferListItem>[]>(() => [
  {
    id: "program",
    header: "Program",
    cell: ({ row }) => {
      const item = row.original;
      return h("div", { class: "space-y-1" }, [
        h(
          "p",
          { class: "text-sm font-semibold text-neutral-900 dark:text-neutral-50" },
          item.programName,
        ),
        h(
          "p",
          { class: "text-xs text-neutral-500 dark:text-neutral-400" },
          formatProgramTypeLabel(item.programType),
        ),
      ]);
    },
  },
  {
    id: "offer",
    header: "Offer",
    cell: ({ row }) => {
      const item = row.original;
      return h(
        "p",
        { class: "text-sm text-neutral-700 break-all text-wrap dark:text-neutral-200 max-w-xs" },
        item.title,
      );
    },
  },
  {
    id: "reward",
    header: "Reward",
    cell: ({ row }) => {
      const item = row.original;
      return h(
        "p",
        { class: "text-sm font-semibold text-neutral-900 dark:text-neutral-50" },
        formatRewardRange(item),
      );
    },
  },
  {
    id: "captured",
    header: "Last captured",
    cell: ({ row }) => {
      const item = row.original;
      if (!item.sourceCaptureDate) {
        return h(
          "span",
          { class: "text-xs text-neutral-500 dark:text-neutral-400" },
          "Not available",
        );
      }

      return h(
        "span",
        { class: "text-sm text-neutral-700 dark:text-neutral-300" },
        formatDate(item.sourceCaptureDate, {
          fallback: item.sourceCaptureDate,
          preserveInputOnError: true,
        }),
      );
    },
  },
  {
    id: "matches",
    header: "KEV matches",
    cell: ({ row }) => {
      const count = row.original.matchedKevCveIds.length;
      return h(
        "span",
        { class: "text-sm font-semibold text-neutral-900 dark:text-neutral-50" },
        count.toLocaleString(),
      );
    },
  },
]);

const handleOfferSelect = (row: TableRow<MarketOfferListItem>) => {
  if (!row?.original) {
    return;
  }

  selectedOffer.value = row.original;
  showOfferModal.value = true;
};

watch(showOfferModal, (open) => {
  if (!open) {
    selectedOffer.value = null;
  }
});
</script>

<template>
  <div class="space-y-8 py-6 max-w-7xl mx-auto">
    <div class="space-y-1">
      <h1 class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
        Market intelligence
      </h1>
      <p class="text-sm text-neutral-500 dark:text-neutral-400">
        Align exploit broker and bug bounty valuations with the Known Exploited Vulnerabilities catalog.
      </p>
    </div>

    <UAlert
      v-if="error"
      color="error"
      icon="i-lucide-alert-triangle"
      title="Unable to load market statistics"
      :description="error.message"
    />

    <div v-else-if="isLoading" class="space-y-8">
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <USkeleton v-for="n in 4" :key="`metric-skeleton-${n}`" class="h-28 rounded-2xl" />
      </div>

      <div class="grid gap-6 lg:grid-cols-2">
        <USkeleton class="h-64 rounded-2xl" />
        <USkeleton class="h-64 rounded-2xl" />
      </div>

      <USkeleton class="h-80 rounded-2xl" />
    </div>

    <div v-else class="space-y-8">
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          title="Mapped offers"
          :value="offerCountLabel"
          icon="i-lucide-link-2"
        />
        <StatCard
          title="Programs tracked"
          :value="programCountLabel"
          icon="i-lucide-users"
        />
        <StatCard
          title="Average reward"
          :value="averageRewardLabel"
          icon="i-lucide-banknote"
        />
        <StatCard
          title="Last capture"
          :value="lastCaptureLabel"
          icon="i-lucide-clock"
        />
      </div>

      <div class="grid gap-6 lg:grid-cols-2">
        <UCard>
          <template #header>
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Program mix
            </p>
          </template>
          <template #default>
            <div v-if="programCounts.length" class="space-y-3">
              <div
                v-for="item in programCounts"
                :key="item.key"
                class="flex items-center justify-between rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
              >
                <span class="text-sm font-medium text-neutral-900 dark:text-neutral-50">
                  {{ item.name }}
                </span>
                <span class="text-sm text-neutral-500 dark:text-neutral-400">
                  {{ item.count.toLocaleString() }}
                </span>
              </div>
            </div>
            <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
              No program data available.
            </p>
          </template>
        </UCard>

        <UCard>
          <template #header>
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Top categories
            </p>
          </template>
          <template #default>
            <div v-if="categoryCounts.length" class="space-y-3">
              <div
                v-for="item in categoryCounts.slice(0, 6)"
                :key="item.key"
                class="flex items-center justify-between rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
              >
                <div>
                  <p class="text-sm font-medium text-neutral-900 dark:text-neutral-50">
                    {{ item.name }}
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ formatCategoryTypeLabel(item.categoryType) }}
                  </p>
                </div>
                <span class="text-sm text-neutral-500 dark:text-neutral-400">
                  {{ item.count.toLocaleString() }}
                </span>
              </div>
            </div>
            <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
              No category data available.
            </p>
          </template>
        </UCard>
      </div>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Mapped market offers
            </p>
            <div class="flex items-center gap-3 text-xs text-neutral-500 dark:text-neutral-400 sm:text-sm">
              <span>{{ offersSummaryLabel }}</span>
              <UBadge
                v-if="activeFilterCount"
                color="primary"
                variant="soft"
                class="font-semibold"
              >
                {{ activeFilterCount }} active {{ activeFilterCount === 1 ? "filter" : "filters" }}
              </UBadge>
            </div>
          </div>
        </template>

        <div class="space-y-6">
          <div class="space-y-4">
            <div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div class="w-full lg:max-w-xl">
                <UInput
                  v-model="searchInput"
                  icon="i-lucide-search"
                  placeholder="Search programs, offers, vendors, or products"
                  size="md"
                />
              </div>
              <div class="flex flex-wrap items-center gap-3 text-xs text-neutral-600 dark:text-neutral-300 sm:text-sm">
                <div class="flex items-center gap-2">
                  <span class="font-medium">Only KEV matches</span>
                  <USwitch
                    v-model="hasKevOnly"
                    size="sm"
                    aria-label="Toggle KEV matches only"
                  />
                </div>
                <UButton
                  color="neutral"
                  variant="ghost"
                  size="sm"
                  :disabled="!activeFilterCount"
                  @click="clearFilters"
                >
                  Clear filters
                </UButton>
              </div>
            </div>

            <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
              <div class="flex flex-wrap items-center gap-2">
                <button
                  v-for="option in programTypeOptions"
                  :key="option.value"
                  type="button"
                  class="rounded-full border px-3 py-1 text-xs font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500"
                  :class="[
                    isProgramTypeSelected(option.value)
                      ? 'border-primary-300 bg-primary-50 text-primary-700 dark:border-primary-500/60 dark:bg-primary-500/10 dark:text-primary-200'
                      : 'border-neutral-200 text-neutral-600 hover:border-primary-200 hover:text-primary-600 dark:border-neutral-800 dark:text-neutral-300 dark:hover:border-primary-500/40 dark:hover:text-primary-200',
                  ]"
                  :aria-pressed="isProgramTypeSelected(option.value)"
                  @click="toggleProgramType(option.value)"
                >
                  {{ option.label }}
                </button>
              </div>

              <div class="flex flex-wrap items-end gap-3">
                <div class="flex items-center gap-2">
                  <UInput
                    v-model="minRewardInput"
                    type="number"
                    inputmode="numeric"
                    placeholder="Min $"
                    size="sm"
                    class="w-28"
                  />
                  <span class="text-xs text-neutral-500 dark:text-neutral-400">to</span>
                  <UInput
                    v-model="maxRewardInput"
                    type="number"
                    inputmode="numeric"
                    placeholder="Max $"
                    size="sm"
                    class="w-28"
                  />
                </div>

                <USelectMenu
                  v-model="sortKey"
                  :items="sortOptionItems"
                  value-key="value"
                  size="sm"
                />

                <USelectMenu
                  v-model="sortDirection"
                  :items="sortDirectionItems"
                  value-key="value"
                  size="sm"
                />
              </div>
            </div>
          </div>

          <UAlert
            v-if="offersError"
            color="error"
            icon="i-lucide-alert-triangle"
            title="Unable to load market offers"
            :description="offersErrorMessage"
          />

          <div v-if="offersPending" class="space-y-3">
            <USkeleton
              v-for="n in 4"
              :key="`offers-skeleton-${n}`"
              class="h-12 rounded-xl"
            />
          </div>
          <div
            v-else-if="!offers.length"
            class="rounded-xl border border-dashed border-neutral-300 p-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:text-neutral-400"
          >
            <p>No market offers match your filters yet.</p>
          </div>
          <div v-else>
            <UTable
              :data="offers"
              :columns="offerColumns"
              :ui="offerTableUi"
              @select="handleOfferSelect"
            />
          </div>

          <div
            v-if="offersTotal > pageSize"
            class="flex justify-end border-t border-neutral-200 pt-4 dark:border-neutral-800"
          >
            <UPagination
              v-model:page="page"
              :items-per-page="pageSize"
              :total="offersTotal"
              :sibling-count="1"
              show-edges
            />
          </div>
        </div>
      </UCard>

      <UCard>
        <template #header>
          <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
            Highest value offers
          </p>
        </template>
        <template #default>
          <div v-if="topOffers.length" class="space-y-4">
            <div
              v-for="offer in topOffers"
              :key="offer.id"
              class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800"
            >
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                    {{ offer.title }}
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ offer.programName }} · {{ formatProgramTypeLabel(offer.programType) }}
                  </p>
                </div>
                <div class="text-right text-sm text-neutral-500 dark:text-neutral-400">
                  <p>
                    {{
                      offer.maxRewardUsd !== null
                        ? currencyFormatter.format(offer.maxRewardUsd)
                        : "—"
                    }}
                  </p>
                  <p v-if="offer.sourceCaptureDate">
                    {{
                      formatDate(offer.sourceCaptureDate, {
                        fallback: offer.sourceCaptureDate,
                        preserveInputOnError: true,
                      })
                    }}
                  </p>
                </div>
              </div>
              <div v-if="offer.targetSummaries.length" class="mt-3 flex flex-wrap gap-2">
                <UBadge
                  v-for="summary in offer.targetSummaries"
                  :key="`target-${offer.id}-${summary}`"
                  color="primary"
                  variant="soft"
                  class="text-xs font-medium"
                >
                  {{ summary }}
                </UBadge>
              </div>
              <div v-else class="mt-3 flex flex-wrap gap-2">
                <UBadge
                  v-for="name in offer.productNames"
                  :key="`product-${offer.id}-${name}`"
                  color="primary"
                  variant="soft"
                  class="text-xs"
                >
                  {{ name }}
                </UBadge>
                <UBadge
                  v-for="vendor in offer.vendorNames"
                  :key="`vendor-${offer.id}-${vendor}`"
                  color="neutral"
                  variant="soft"
                  class="text-xs"
                >
                  {{ vendor }}
                </UBadge>
              </div>
              <ULink
                v-if="offer.sourceUrl"
                :href="offer.sourceUrl"
                target="_blank"
                rel="noopener noreferrer"
                class="mt-3 inline-flex items-center gap-2 text-sm font-medium text-primary-600 transition hover:text-primary-500 dark:text-primary-300"
              >
                View source
                <UIcon name="i-lucide-arrow-up-right" class="size-4" />
              </ULink>
            </div>
          </div>
          <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
            No offer data available.
          </p>
        </template>
      </UCard>
    </div>

    <MarketOfferDetailModal
      v-model:open="showOfferModal"
      :offer="selectedOffer"
    />
  </div>
</template>
