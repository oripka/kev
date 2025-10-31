<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { formatDistanceToNowStrict, parseISO, subDays } from "date-fns";
import { catalogSourceBadgeMap as sourceBadgeMap } from "~/constants/catalogSources";
import type { CatalogSource, KevEntryDetail, KevEntrySummary } from "~/types";
import { useKevData } from "~/composables/useKevData";
import { useDateDisplay } from "~/composables/useDateDisplay";

const rangeEnd = new Date();
const rangeStart = subDays(rangeEnd, 14);
const rangeStartIso = rangeStart.toISOString();
const rangeEndIso = rangeEnd.toISOString();

const { formatDate, formatDateRange } = useDateDisplay();

const rangeLabel = computed(() =>
  formatDateRange(rangeStart, rangeEnd, { fallback: "Date unavailable" })
);

const queryParams = computed(() => ({
  fromDate: rangeStartIso,
  toDate: rangeEndIso,
  limit: 1_000,
  source: "kev,enisa,historic,custom,metasploit",
}));

const {
  entries,
  counts,
  totalEntries,
  entryLimit,
  updatedAt,
  pending,
  error,
  refresh,
  getWellKnownCveName,
} = useKevData(queryParams);

const entryCount = computed(() => entries.value.length);

const uniqueVendors = computed(() => {
  const seen = new Set<string>();
  for (const entry of entries.value) {
    const key = entry.vendorKey || entry.vendor;
    if (key) {
      seen.add(key);
    }
  }
  return seen.size;
});

const uniqueProducts = computed(() => {
  const seen = new Set<string>();
  for (const entry of entries.value) {
    const key = entry.productKey || entry.product;
    if (key) {
      seen.add(key);
    }
  }
  return seen.size;
});

const highSeverityLevels: Set<Exclude<KevEntrySummary["cvssSeverity"], null>> = new Set([
  "High",
  "Critical",
]);

const highSeverityCount = computed(
  () =>
    entries.value.filter((entry) => {
      if (!entry.cvssSeverity) {
        return false;
      }
      return highSeverityLevels.has(entry.cvssSeverity);
    }).length
);

const highSeverityShare = computed(() => {
  if (!entryCount.value) {
    return 0;
  }
  return (highSeverityCount.value / entryCount.value) * 100;
});

const averageCvssScore = computed(() => {
  const scores = entries.value
    .map((entry) => entry.cvssScore)
    .filter((score): score is number => typeof score === "number" && Number.isFinite(score));

  if (!scores.length) {
    return null;
  }

  const total = scores.reduce((sum, score) => sum + score, 0);
  return total / scores.length;
});

const ransomwareCount = computed(() =>
  entries.value.filter((entry) => typeof entry.ransomwareUse === "string" && entry.ransomwareUse.trim().length > 0)
    .length
);

const internetExposedCount = computed(() =>
  entries.value.filter((entry) => entry.internetExposed).length
);

const ransomwareShare = computed(() => {
  if (!entryCount.value) {
    return 0;
  }
  return (ransomwareCount.value / entryCount.value) * 100;
});

const internetExposedShare = computed(() => {
  if (!entryCount.value) {
    return 0;
  }
  return (internetExposedCount.value / entryCount.value) * 100;
});

const topVendor = computed(() => counts.value.vendor.at(0) ?? null);
const topProduct = computed(() => counts.value.product.at(0) ?? null);
const topDomain = computed(() => counts.value.domain.at(0) ?? null);

const limitReached = computed(
  () => entryCount.value >= entryLimit.value && totalEntries.value > entryLimit.value
);

const lastUpdatedLabel = computed(() => {
  if (!updatedAt.value) {
    return "No imports yet";
  }
  const parsed = parseISO(updatedAt.value);
  if (Number.isNaN(parsed.getTime())) {
    return updatedAt.value;
  }
  return formatDistanceToNowStrict(parsed, { addSuffix: true });
});

const cvssSeverityColors: Record<Exclude<KevEntrySummary["cvssSeverity"], null>, string> = {
  None: "success",
  Low: "primary",
  Medium: "warning",
  High: "error",
  Critical: "error",
};

const formatCvssScoreValue = (score: number | null) =>
  typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : null;

const formatCvssScoreLabel = (score: number | null) => formatCvssScoreValue(score) ?? "—";

const formatEpssScoreValue = (score: number | null) =>
  typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : null;

const formatEpssScoreLabel = (score: number | null) => formatEpssScoreValue(score) ?? "—";

const formatDateLabel = (value: string | null) =>
  formatDate(value, {
    fallback: "Date unavailable",
    preserveInputOnError: true,
  });

const formatRelativeDate = (value: string | null) => {
  if (!value) {
    return null;
  }
  const parsed = parseISO(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return formatDistanceToNowStrict(parsed, { addSuffix: true });
};

const formatOptionalTimestamp = (value: string | null) =>
  formatDate(value, {
    fallback: "Not available",
    preserveInputOnError: true,
  });

const buildCvssLabel = (
  severity: KevEntrySummary["cvssSeverity"],
  score: number | null
) => {
  const parts: string[] = [];

  if (severity) {
    parts.push(severity);
  }

  const formatted = formatCvssScoreValue(score);
  if (formatted) {
    parts.push(formatted);
  }

  if (!parts.length) {
    parts.push("Unknown");
  }

  return parts.join(" ");
};

type DetailQuickFilterPayload = {
  filters?: Partial<{
    domain: string;
    exploit: string;
    vulnerability: string;
    vendor: string;
    product: string;
  }>;
  source?: CatalogSource;
  year?: number;
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

const closeDetails = () => {
  showDetails.value = false;
};

const router = useRouter();

const handleDetailQuickFilter = (payload: DetailQuickFilterPayload) => {
  const query: Record<string, string> = {};

  const { filters: filterPayload, source, year } = payload;

  if (filterPayload) {
    if (filterPayload.domain) {
      query.domain = filterPayload.domain;
    }
    if (filterPayload.exploit) {
      query.exploit = filterPayload.exploit;
    }
    if (filterPayload.vulnerability) {
      query.vulnerability = filterPayload.vulnerability;
    }
    if (filterPayload.vendor) {
      query.vendor = filterPayload.vendor;
    }
    if (filterPayload.product) {
      query.product = filterPayload.product;
    }
  }

  if (source) {
    query.source = source;
  }

  if (typeof year === "number" && Number.isFinite(year)) {
    query.year = String(year);
  }

  closeDetails();

  void router.push({
    path: "/",
    query,
  });
};

watch(showDetails, (value) => {
  if (!value) {
    detailEntry.value = null;
    detailLoading.value = false;
    detailError.value = null;
  }
});
</script>

<template>
  <UPage>
    <UPageBody>
      <div class="mx-auto flex w-full max-w-6xl flex-col gap-6 px-6 py-6">
        <div class="space-y-1">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Two-week activity
          </p>
          <h1 class="text-3xl font-semibold text-neutral-900 dark:text-neutral-50">
            Recent exploited vulnerabilities
          </h1>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Entries added in the last 14 days ({{ rangeLabel }}). Updated {{ lastUpdatedLabel }}.
          </p>
        </div>

        <UCard class="border border-primary-200/60 bg-primary-50/60 shadow-sm dark:border-primary-900/60 dark:bg-primary-950/20">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                  Two-week snapshot
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Quick metrics for vulnerabilities published or updated in the last fortnight.
                </p>
              </div>
              <UBadge color="primary" variant="soft" class="text-sm font-semibold">
                {{ entryCount.toLocaleString() }} CVEs
              </UBadge>
            </div>
          </template>

          <div class="space-y-6">
            <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div
                class="rounded-lg border border-white/40 bg-white/60 p-4 shadow-sm dark:border-neutral-800/60 dark:bg-neutral-950/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Unique vendors
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ uniqueVendors.toLocaleString() }}
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Represented across the recent vulnerabilities.
                </p>
              </div>
              <div
                class="rounded-lg border border-white/40 bg-white/60 p-4 shadow-sm dark:border-neutral-800/60 dark:bg-neutral-950/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Unique products
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ uniqueProducts.toLocaleString() }}
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Distinct products linked to active exploits.
                </p>
              </div>
              <div
                class="rounded-lg border border-white/40 bg-white/60 p-4 shadow-sm dark:border-neutral-800/60 dark:bg-neutral-950/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  High &amp; critical share
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ highSeverityShare.toFixed(0) }}%
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  {{ highSeverityCount.toLocaleString() }} CVEs rated High or Critical.
                </p>
              </div>
              <div
                class="rounded-lg border border-white/40 bg-white/60 p-4 shadow-sm dark:border-neutral-800/60 dark:bg-neutral-950/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Average CVSS
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ averageCvssScore !== null ? averageCvssScore.toFixed(1) : "—" }}
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Across CVEs with published CVSS scores.
                </p>
              </div>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div
                class="rounded-lg border border-white/40 bg-white/60 p-4 shadow-sm dark:border-neutral-800/60 dark:bg-neutral-950/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Ransomware linked
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ ransomwareShare.toFixed(0) }}%
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  {{ ransomwareCount.toLocaleString() }} CVEs mention ransomware activity.
                </p>
              </div>
              <div
                class="rounded-lg border border-white/40 bg-white/60 p-4 shadow-sm dark:border-neutral-800/60 dark:bg-neutral-950/40"
              >
                <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Internet exposed
                </p>
                <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ internetExposedShare.toFixed(0) }}%
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  {{ internetExposedCount.toLocaleString() }} CVEs affect internet-facing services.
                </p>
              </div>
            </div>

            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex flex-wrap gap-3 text-sm text-neutral-600 dark:text-neutral-300">
                <span v-if="topVendor">
                  Top vendor: <span class="font-semibold">{{ topVendor.name }}</span>
                  <span class="text-xs text-neutral-500 dark:text-neutral-400">
                    ({{ topVendor.count.toLocaleString() }} CVEs)
                  </span>
                </span>
                <span v-if="topProduct">
                  Top product: <span class="font-semibold">{{ topProduct.name }}</span>
                  <span class="text-xs text-neutral-500 dark:text-neutral-400">
                    ({{ topProduct.count.toLocaleString() }} CVEs)
                  </span>
                </span>
                <span v-if="topDomain">
                  Dominant domain: <span class="font-semibold">{{ topDomain.name }}</span>
                </span>
              </div>
              <div class="flex items-center gap-3">
                <UBadge
                  v-if="limitReached"
                  color="warning"
                  variant="soft"
                  class="text-xs font-semibold"
                >
                  Showing first {{ entryLimit.toLocaleString() }} of {{ totalEntries.toLocaleString() }} matches
                </UBadge>
                <UButton color="primary" variant="soft" size="sm" :loading="pending" @click="refresh">
                  Refresh data
                </UButton>
              </div>
            </div>
          </div>
        </UCard>

        <section class="space-y-4">
          <div class="flex items-center justify-between gap-3">
            <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">
              Vulnerabilities detected
            </h2>
            <span class="text-sm text-neutral-500 dark:text-neutral-400">
              {{ entryCount.toLocaleString() }} results
            </span>
          </div>

          <UAlert
            v-if="error"
            color="rose"
            variant="soft"
            icon="i-lucide-triangle-alert"
            class="border border-rose-200/60 bg-rose-50/60 dark:border-rose-900/60 dark:bg-rose-950/20"
          >
            <template #title>Unable to load recent vulnerabilities</template>
            <template #description>
              {{ error.message }}
            </template>
          </UAlert>

          <div v-else>
            <div v-if="pending" class="grid gap-4 md:grid-cols-2">
              <UCard v-for="index in 4" :key="index" class="space-y-4">
                <USkeleton class="h-6 w-2/3" />
                <USkeleton class="h-4 w-full" />
                <USkeleton class="h-4 w-1/2" />
                <div class="flex gap-2">
                  <USkeleton class="h-6 w-20" />
                  <USkeleton class="h-6 w-20" />
                </div>
              </UCard>
            </div>

            <div
              v-else-if="!entries.length"
              class="rounded-lg border border-dashed border-neutral-300 bg-white/60 p-10 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900/50 dark:text-neutral-400"
            >
              No vulnerabilities were published in the selected window.
            </div>

            <div v-else class="grid gap-4 md:grid-cols-2">
              <UCard
                v-for="entry in entries"
                :key="entry.id"
                role="button"
                tabindex="0"
                :aria-label="`View details for ${entry.vulnerabilityName || entry.cveId}`"
                class="group flex h-full cursor-pointer flex-col gap-4 transition hover:-translate-y-0.5 hover:shadow-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500"
                @click="openDetails(entry)"
                @keydown.enter.prevent.stop="openDetails(entry)"
                @keydown.space.prevent.stop="openDetails(entry)"
              >
                <div class="space-y-2">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <p class="text-sm font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                      {{ entry.cveId }}
                    </p>
                    <div class="flex flex-wrap items-center gap-2">
                      <UBadge
                        v-for="source in entry.sources"
                        :key="source"
                        :color="sourceBadgeMap[source].color"
                        variant="soft"
                        class="text-xs font-semibold"
                      >
                        {{ sourceBadgeMap[source].label }}
                      </UBadge>
                    </div>
                  </div>
                  <h3 class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                    {{ entry.vulnerabilityName || entry.cveId }}
                  </h3>
                  <p class="text-sm text-neutral-600 dark:text-neutral-300">
                    {{ entry.vendor }} · {{ entry.product }}
                  </p>
                  <p class="text-sm text-neutral-500 dark:text-neutral-400 pb-2">
                    Added {{ formatDateLabel(entry.dateAdded) }}<span v-if="formatRelativeDate(entry.dateAdded)">
                      · {{ formatRelativeDate(entry.dateAdded) }}</span
                    >
                  </p>
                </div>

                <div class="mt-auto space-y-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <UBadge
                      v-if="entry.cvssSeverity"
                      :color="cvssSeverityColors[entry.cvssSeverity]"
                      variant="soft"
                      class="text-xs font-semibold"
                    >
                      {{ entry.cvssSeverity }} · {{ formatCvssScoreLabel(entry.cvssScore) }}
                    </UBadge>
                    <UBadge v-else color="neutral" variant="soft" class="text-xs font-semibold">
                      CVSS unavailable
                    </UBadge>
                    <UBadge color="neutral" variant="soft" class="text-xs font-semibold">
                      EPSS {{ formatEpssScoreLabel(entry.epssScore) }}
                    </UBadge>
                    <UBadge
                      v-if="entry.internetExposed"
                      color="warning"
                      variant="soft"
                      class="text-xs font-semibold"
                    >
                      Internet exposed
                    </UBadge>
                    <UBadge
                      v-if="entry.ransomwareUse"
                      color="error"
                      variant="soft"
                      class="text-xs font-semibold"
                    >
                      Ransomware noted
                    </UBadge>
                  </div>
                  <div v-if="entry.domainCategories.length" class="flex flex-wrap gap-2">
                    <UBadge
                      v-for="domain in entry.domainCategories"
                      :key="domain"
                      color="neutral"
                      variant="outline"
                      class="text-xs"
                    >
                      {{ domain }}
                    </UBadge>
                  </div>
                </div>
              </UCard>
            </div>
          </div>
        </section>
      </div>
      <CatalogDetailModal
        v-model:open="showDetails"
        :entry="detailEntry"
        :loading="detailLoading"
        :error="detailError"
        :source-badge-map="sourceBadgeMap"
        :cvss-severity-colors="cvssSeverityColors"
        :build-cvss-label="buildCvssLabel"
        :format-epss-score="formatEpssScoreValue"
        :format-optional-timestamp="formatOptionalTimestamp"
        :get-well-known-cve-name="getWellKnownCveName"
        @close="closeDetails"
        @quick-filter="handleDetailQuickFilter"
      />
    </UPageBody>
  </UPage>
</template>
