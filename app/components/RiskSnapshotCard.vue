<script setup lang="ts">
import { computed } from "vue";
import type { KevEntrySummary } from "~/types";
import type {
  TrackedProductSummary,
  TrackedProductSeveritySlice
} from "~/composables/useTrackedProducts";


import type {
  LatestAdditionSortKey,
  LatestAdditionSortOption,
  LatestAdditionSummary,
  SeverityDistributionDatum,
  SeverityKey,
  SourceBadgeMap,
  StatTrend,
} from "~/types/dashboard";



type FocusContext = {
  active: boolean;
  summary: TrackedProductSummary | null;
};

const severityBarClassMap: Record<string, string> = {
  error: "bg-rose-500/80",
  warning: "bg-amber-500/80",
  primary: "bg-sky-500/80",
  success: "bg-emerald-500/80",
  neutral: "bg-neutral-500/70",
};

const severityDotClassMap: Record<string, string> = {
  error: "bg-rose-500",
  warning: "bg-amber-500",
  primary: "bg-sky-500",
  success: "bg-emerald-500",
  neutral: "bg-neutral-500",
};


const props = defineProps<{
  matchingResultsLabel: string;
  periodLabel: string;
  highSeverityShareLabel: string;
  highSeveritySummary: string;
  highSeverityTrend: StatTrend | null;
  averageCvssLabel: string;
  averageCvssSummary: string;
  averageCvssTrend: StatTrend | null;
  ransomwareShareLabel: string;
  ransomwareSummary: string;
  ransomwareTrend: StatTrend | null;
  internetExposedShareLabel: string;
  internetExposedSummary: string;
  internetExposedTrend: StatTrend | null;
  severityDistribution: SeverityDistributionDatum[];
  latestAdditionSummaries: LatestAdditionSummary[];
  latestAdditionNotes: string[];
  latestAdditionSortKey: LatestAdditionSortKey;
  latestAdditionSortOptions: LatestAdditionSortOption[];
  trackedProductsReady: boolean;
  sourceBadgeMap: SourceBadgeMap;
  showRiskDetails: boolean;
  focusContext?: FocusContext | null;
}>();

const emit = defineEmits<{
  (event: "update:show-risk-details", value: boolean): void;
  (event: "update:latest-addition-sort-key", value: LatestAdditionSortKey): void;
  (event: "open-details", entry: KevEntrySummary): void;
  (event: "add-to-tracked", entry: KevEntrySummary): void;
}>();

const riskDetails = computed({
  get: () => props.showRiskDetails,
  set: (value: boolean) => emit("update:show-risk-details", value),
});

const latestAdditionSortKey = computed({
  get: () => props.latestAdditionSortKey,
  set: (value: LatestAdditionSortKey) => emit("update:latest-addition-sort-key", value),
});

const severityMetaMap: Record<SeverityKey, { icon: string; class: string; label: string }> = {
  Critical: {
    icon: "i-lucide-radiation",
    class: "text-rose-600 dark:text-rose-400",
    label: "Critical severity",
  },
  High: {
    icon: "i-lucide-alert-triangle",
    class: "text-amber-500 dark:text-amber-400",
    label: "High severity",
  },
  Medium: {
    icon: "i-lucide-hexagon",
    class: "text-orange-500 dark:text-orange-400",
    label: "Medium severity",
  },
  Low: {
    icon: "i-lucide-shield",
    class: "text-sky-500 dark:text-sky-400",
    label: "Low severity",
  },
  None: {
    icon: "i-lucide-shield-check",
    class: "text-emerald-500 dark:text-emerald-400",
    label: "No severity impact",
  },
  Unknown: {
    icon: "i-lucide-help-circle",
    class: "text-neutral-400 dark:text-neutral-500",
    label: "Unknown severity",
  },
};

const trendMetaMap: Record<NonNullable<StatTrend>["direction"], { icon: string; class: string }> = {
  up: { icon: "i-lucide-trending-up", class: "text-rose-500 dark:text-rose-400" },
  down: { icon: "i-lucide-trending-down", class: "text-emerald-500 dark:text-emerald-400" },
  flat: { icon: "i-lucide-arrow-right", class: "text-neutral-500 dark:text-neutral-400" },
};

const epssFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
});

const resolveTrendMeta = (trend: StatTrend | null) => {
  if (!trend) {
    return null;
  }

  return {
    ...trendMetaMap[trend.direction],
    deltaLabel: trend.deltaLabel,
  };
};

const resolveSeverityMeta = (severity: KevEntrySummary["cvssSeverity"]) => {
  const key = (severity ?? "Unknown") as SeverityKey;
  return severityMetaMap[key];
};

const formatEpssScore = (value: number | null | undefined) => {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return null;
  }

  return epssFormatter.format(value * 100);
};

const openDetails = (entry: KevEntrySummary) => {
  emit("open-details", entry);
};

const focusSummary = computed(() => props.focusContext?.summary ?? null);

const focusSeveritySlices = computed<TrackedProductSeveritySlice[]>(() => {
  const summary = focusSummary.value;
  if (!summary || !summary.severityBreakdown.length) {
    return [];
  }
  return summary.severityBreakdown;
});
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="space-y-1">
          <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
            Risk snapshot
          </p>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Quick metrics for the current selection
          </p>
        </div>
        <div class="flex items-center gap-2">
          <UBadge color="primary" variant="soft" class="text-sm font-semibold">
            {{ props.matchingResultsLabel }} matching exploits
          </UBadge>
          <UBadge
            v-if="props.focusContext?.active"
            color="primary"
            variant="ghost"
            class="text-xs font-semibold"
          >
            Focus: My software
          </UBadge>
        </div>
      </div>
    </template>

    <div class="space-y-6">
      <div
        v-if="props.focusContext?.active && focusSummary?.hasData"
        class="space-y-3 rounded-lg border border-primary-200/80 bg-primary-50/60 p-4 text-xs text-neutral-700 dark:border-primary-500/50 dark:bg-primary-500/10 dark:text-neutral-200"
      >
        <div class="flex flex-wrap items-center gap-2 font-semibold">
          <UBadge color="primary" variant="soft" class="font-semibold">
            {{ focusSummary.productCount.toLocaleString() }} tracked product{{
              focusSummary.productCount === 1 ? '' : 's'
            }}
          </UBadge>
          <UBadge color="neutral" variant="soft" class="font-semibold">
            {{ focusSummary.totalCount.toLocaleString() }} CVEs in scope
          </UBadge>
          <UBadge color="primary" variant="soft" class="font-semibold">
            {{ focusSummary.recentCount.toLocaleString() }} new ·
            {{ focusSummary.recentWindowLabel }}
          </UBadge>
        </div>
        <div v-if="focusSeveritySlices.length" class="space-y-2">
          <div class="h-2 overflow-hidden rounded-full bg-primary-200/60 dark:bg-primary-500/30">
            <div
              v-for="slice in focusSeveritySlices"
              :key="slice.key"
              class="h-full"
              :class="severityBarClassMap[slice.color] ?? severityBarClassMap.neutral"
              :style="{ width: `${slice.percent}%` }"
            />
          </div>
          <div class="flex flex-wrap gap-2 text-[11px]">
            <span
              v-for="slice in focusSeveritySlices"
              :key="slice.key"
              class="inline-flex items-center gap-1 rounded-full border border-neutral-200 bg-white/80 px-2 py-0.5 dark:border-neutral-700 dark:bg-neutral-900/60"
            >
              <span
                class="h-2 w-2 rounded-full"
                :class="severityDotClassMap[slice.color] ?? severityDotClassMap.neutral"
              />
              {{ slice.label }} · {{ slice.count.toLocaleString() }}
            </span>
          </div>
        </div>
      </div>

      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            High &amp; critical share
          </p>
          <div class="mt-2 flex items-center gap-2">
            <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
              {{ props.highSeverityShareLabel }}
            </p>
            <span
              v-if="resolveTrendMeta(props.highSeverityTrend)"
              class="flex items-center gap-1 text-xs font-semibold"
              :class="resolveTrendMeta(props.highSeverityTrend)?.class"
            >
              <UIcon
                :name="resolveTrendMeta(props.highSeverityTrend)?.icon"
                class="h-3.5 w-3.5"
                aria-hidden="true"
              />
              <span>{{ resolveTrendMeta(props.highSeverityTrend)?.deltaLabel }}</span>
            </span>
          </div>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.highSeveritySummary }}
          </p>
        </div>
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Average CVSS
          </p>
          <div class="mt-2 flex items-center gap-2">
            <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
              {{ props.averageCvssLabel }}
            </p>
            <span
              v-if="resolveTrendMeta(props.averageCvssTrend)"
              class="flex items-center gap-1 text-xs font-semibold"
              :class="resolveTrendMeta(props.averageCvssTrend)?.class"
            >
              <UIcon
                :name="resolveTrendMeta(props.averageCvssTrend)?.icon"
                class="h-3.5 w-3.5"
                aria-hidden="true"
              />
              <span>{{ resolveTrendMeta(props.averageCvssTrend)?.deltaLabel }}</span>
            </span>
          </div>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.averageCvssSummary }}
          </p>
        </div>
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Ransomware-linked CVEs
          </p>
          <div class="mt-2 flex items-center gap-2">
            <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
              {{ props.ransomwareShareLabel }}
            </p>
            <span
              v-if="resolveTrendMeta(props.ransomwareTrend)"
              class="flex items-center gap-1 text-xs font-semibold"
              :class="resolveTrendMeta(props.ransomwareTrend)?.class"
            >
              <UIcon
                :name="resolveTrendMeta(props.ransomwareTrend)?.icon"
                class="h-3.5 w-3.5"
                aria-hidden="true"
              />
              <span>{{ resolveTrendMeta(props.ransomwareTrend)?.deltaLabel }}</span>
            </span>
          </div>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.ransomwareSummary }}
          </p>
        </div>
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Internet exposure share
          </p>
          <div class="mt-2 flex items-center gap-2">
            <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
              {{ props.internetExposedShareLabel }}
            </p>
            <span
              v-if="resolveTrendMeta(props.internetExposedTrend)"
              class="flex items-center gap-1 text-xs font-semibold"
              :class="resolveTrendMeta(props.internetExposedTrend)?.class"
            >
              <UIcon
                :name="resolveTrendMeta(props.internetExposedTrend)?.icon"
                class="h-3.5 w-3.5"
                aria-hidden="true"
              />
              <span>{{ resolveTrendMeta(props.internetExposedTrend)?.deltaLabel }}</span>
            </span>
          </div>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.internetExposedSummary }}
          </p>
        </div>
      </div>

      <UCollapsible v-model:open="riskDetails" :unmount-on-hide="false" class="flex flex-col gap-4">
        <UButton
          color="neutral"
          variant="outline"
          size="sm"
          :trailing-icon="riskDetails ? 'i-lucide-chevron-up' : 'i-lucide-chevron-down'"
          block
        >
          {{ riskDetails ? 'Hide detailed breakdown' : 'Show detailed breakdown' }}
        </UButton>

        <template #content>
          <div class="grid gap-6 lg:grid-cols-5">
            <div class="space-y-4 lg:col-span-3">
              <div class="flex items-center justify-between gap-3">
                <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
                  CVSS severity mix
                </p>
                <UBadge
                  v-if="props.severityDistribution.length"
                  color="neutral"
                  variant="soft"
                  class="text-xs font-semibold"
                >
                  {{ props.matchingResultsLabel }} CVEs
                </UBadge>
              </div>
              <div v-if="props.severityDistribution.length" class="space-y-3">
                <div
                  v-for="item in props.severityDistribution"
                  :key="item.key"
                  class="space-y-2 rounded-lg border border-neutral-200 bg-white/60 p-3 dark:border-neutral-800 dark:bg-neutral-900/40"
                >
                  <div class="flex items-center justify-between gap-3">
                    <div class="flex items-center gap-2">
                      <UBadge :color="item.color" variant="soft" class="font-semibold">
                        {{ item.label }}
                      </UBadge>
                      <span class="text-xs text-neutral-500 dark:text-neutral-400">
                        {{ item.count.toLocaleString() }} CVEs
                      </span>
                    </div>
                    <span class="text-xs font-semibold text-neutral-600 dark:text-neutral-300">
                      {{ item.percentLabel }}%
                    </span>
                  </div>
                  <UProgress :model-value="item.percent" :max="100" :color="item.color" size="sm" />
                </div>
              </div>
              <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                CVSS severity data is not available for the current selection.
              </p>
            </div>

            <div class="space-y-4 lg:col-span-2">
              <div class="space-y-3 rounded-lg border border-neutral-200 bg-white/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div class="flex items-center gap-2">
                    <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
                      Latest additions
                    </p>
                    <UBadge
                      v-if="props.latestAdditionSummaries.length"
                      color="primary"
                      variant="soft"
                      class="text-xs font-semibold"
                    >
                      {{ props.latestAdditionSummaries.length }} shown
                    </UBadge>
                  </div>
                  <div v-if="props.latestAdditionSummaries.length" class="flex items-center gap-2">
                    <span class="hidden text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 md:block">
                      Sort by
                    </span>
                    <div class="flex items-center gap-1 rounded-lg bg-neutral-100 p-1 dark:bg-neutral-900/60">
                      <UButton
                        v-for="option in props.latestAdditionSortOptions"
                        :key="option.value"
                        :color="latestAdditionSortKey === option.value ? 'primary' : 'neutral'"
                        :variant="latestAdditionSortKey === option.value ? 'solid' : 'ghost'"
                        size="xs"
                        :icon="option.icon"
                        class="text-xs"
                        @click="setSortKey(option.value)"
                      >
                        {{ option.label }}
                      </UButton>
                    </div>
                  </div>
                </div>
                <div v-if="props.latestAdditionSummaries.length" class="space-y-3">
                  <div
                    v-for="item in props.latestAdditionSummaries"
                    :key="item.entry.cveId"
                    class="space-y-3 rounded-lg border border-neutral-200 bg-white/80 p-3 dark:border-neutral-800 dark:bg-neutral-900/60"
                  >
                    <div class="flex items-start justify-between gap-3">
                      <div class="space-y-1">
                        <div class="flex items-center gap-2">
                          <span
                            class="flex h-6 w-6 items-center justify-center rounded-full bg-neutral-100 dark:bg-neutral-900/70"
                            :aria-label="resolveSeverityMeta(item.entry.cvssSeverity).label"
                          >
                            <UIcon
                              :name="resolveSeverityMeta(item.entry.cvssSeverity).icon"
                              class="h-3.5 w-3.5"
                              :class="resolveSeverityMeta(item.entry.cvssSeverity).class"
                              aria-hidden="true"
                            />
                          </span>
                          <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                            {{ item.entry.vulnerabilityName }}
                          </p>
                        </div>
                        <p v-if="item.wellKnown" class="text-xs font-medium text-primary-600 dark:text-primary-400">
                          {{ item.wellKnown }}
                        </p>
                        <p class="text-xs text-neutral-500 dark:text-neutral-400">
                          {{ item.vendorProduct }}
                        </p>
                      </div>
                      <div class="flex flex-col items-end gap-2 text-right">
                        <UBadge color="primary" variant="soft" class="text-xs font-semibold">
                          {{ item.dateLabel }}
                        </UBadge>
                        <UBadge
                          v-if="item.internetExposed"
                          color="warning"
                          variant="soft"
                          class="text-xs font-semibold"
                        >
                          Internet-exposed
                        </UBadge>
                      </div>
                    </div>

                    <div class="flex flex-wrap items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
                      <UBadge color="neutral" variant="soft" class="font-semibold">
                        {{ item.entry.cveId }}
                      </UBadge>
                      <UBadge
                        v-if="formatEpssScore(item.entry.epssScore)"
                        color="primary"
                        variant="soft"
                        class="font-semibold"
                      >
                        EPSS {{ formatEpssScore(item.entry.epssScore) }}%
                      </UBadge>
                      <UBadge
                        v-if="typeof item.entry.cvssScore === 'number' && Number.isFinite(item.entry.cvssScore)"
                        color="neutral"
                        variant="soft"
                        class="font-semibold"
                      >
                        CVSS {{ item.entry.cvssScore.toFixed(1) }}
                      </UBadge>
                    </div>

                    <div class="flex flex-wrap gap-2">
                      <UBadge
                        v-for="source in item.sources"
                        :key="source"
                        :color="props.sourceBadgeMap[source]?.color ?? 'neutral'"
                        variant="soft"
                        class="text-xs font-semibold"
                      >
                        {{ props.sourceBadgeMap[source]?.label ?? source.toUpperCase() }}
                      </UBadge>
                    </div>

                    <div class="flex flex-wrap justify-end gap-2">
                      <UButton
                        color="neutral"
                        variant="ghost"
                        size="xs"
                        icon="i-lucide-eye"
                        @click="openDetails(item.entry)"
                      >
                        View details
                      </UButton>
                      <UButton
                        :color="item.isTracked ? 'neutral' : 'primary'"
                        :variant="item.isTracked ? 'soft' : 'solid'"
                        size="xs"
                        :icon="item.isTracked ? 'i-lucide-check' : 'i-lucide-plus'"
                        :disabled="!props.trackedProductsReady || item.isTracked"
                        @click="addToTracked(item.entry)"
                      >
                        {{ item.isTracked ? 'Tracked' : 'Track software' }}
                      </UButton>
                    </div>
                  </div>
                </div>
                <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                  No entries match the current filters yet.
                </p>

                <div
                  v-if="props.latestAdditionNotes.length"
                  class="space-y-2 rounded-lg border border-dashed border-neutral-200 bg-neutral-100/70 p-3 text-xs text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/40 dark:text-neutral-300"
                >
                  <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                    Priority notes
                  </p>
                  <ul class="space-y-2">
                    <li
                      v-for="note in props.latestAdditionNotes"
                      :key="note"
                      class="flex items-start gap-2"
                    >
                      <UIcon
                        name="i-lucide-info"
                        class="mt-0.5 h-3.5 w-3.5 text-primary-500 dark:text-primary-400"
                        aria-hidden="true"
                      />
                      <span class="leading-snug">{{ note }}</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </template>
      </UCollapsible>
    </div>
  </UCard>
</template>
