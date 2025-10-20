<script setup lang="ts">
import { computed } from "vue";
import type { KevEntrySummary } from "~/types";
import type { TrackedProductSummary } from "~/composables/useTrackedProducts";
import type {
  LatestAdditionSortKey,
  LatestAdditionSortOption,
  LatestAdditionSummary,
  SeverityDistributionDatum,
  SourceBadgeMap,
  StatTrend,
} from "~/types/dashboard";

const props = defineProps<{
  open: boolean;
  isBusy: boolean;
  showRiskDetails: boolean;
  showTrendLines: boolean;
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
  catalogUpdatedAt: string;
  entries: KevEntrySummary[];
  focusContext?: { active: boolean; summary: TrackedProductSummary | null };
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "update:show-risk-details", value: boolean): void;
  (event: "update:show-trend-lines", value: boolean): void;
  (event: "update:latest-addition-sort-key", value: LatestAdditionSortKey): void;
  (event: "open-details", entry: KevEntrySummary): void;
  (event: "add-to-tracked", entry: KevEntrySummary): void;
}>();

const open = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const showRiskDetails = computed({
  get: () => props.showRiskDetails,
  set: (value: boolean) => emit("update:show-risk-details", value),
});

const showTrendLines = computed({
  get: () => props.showTrendLines,
  set: (value: boolean) => emit("update:show-trend-lines", value),
});

const latestAdditionSortKey = computed({
  get: () => props.latestAdditionSortKey,
  set: (value: LatestAdditionSortKey) => emit("update:latest-addition-sort-key", value),
});

const handleOpenDetails = (entry: KevEntrySummary) => {
  emit("open-details", entry);
};

const handleAddToTracked = (entry: KevEntrySummary) => {
  emit("add-to-tracked", entry);
};
</script>

<template>
  <USlideover
    v-model:open="open"
    title="Trend explorer"
    description="Visualise how the filtered vulnerabilities accumulate over time."
    :ui="{ content: 'max-w-4xl' }"
    :unmount-on-hide="false"
  >
    <template #body>
      <div class="relative space-y-6">
        <div
          v-if="props.isBusy"
          class="pointer-events-none absolute inset-0 z-10 rounded-xl bg-neutral-200/70 backdrop-blur-sm dark:bg-neutral-800/60"
        />

        <RiskSnapshotCard
          v-model:show-risk-details="showRiskDetails"
          v-model:latest-addition-sort-key="latestAdditionSortKey"
          :matching-results-label="props.matchingResultsLabel"
          :period-label="props.periodLabel"
          :high-severity-share-label="props.highSeverityShareLabel"
          :high-severity-summary="props.highSeveritySummary"
          :high-severity-trend="props.highSeverityTrend"
          :average-cvss-label="props.averageCvssLabel"
          :average-cvss-summary="props.averageCvssSummary"
          :average-cvss-trend="props.averageCvssTrend"
          :ransomware-share-label="props.ransomwareShareLabel"
          :ransomware-summary="props.ransomwareSummary"
          :ransomware-trend="props.ransomwareTrend"
          :internet-exposed-share-label="props.internetExposedShareLabel"
          :internet-exposed-summary="props.internetExposedSummary"
          :internet-exposed-trend="props.internetExposedTrend"
          :severity-distribution="props.severityDistribution"
          :latest-addition-summaries="props.latestAdditionSummaries"
          :latest-addition-notes="props.latestAdditionNotes"
          :latest-addition-sort-options="props.latestAdditionSortOptions"
          :tracked-products-ready="props.trackedProductsReady"
          :source-badge-map="props.sourceBadgeMap"
          :focus-context="props.focusContext"
          @open-details="handleOpenDetails"
          @add-to-tracked="handleAddToTracked"
        />

        <FilteredTrendPanel v-model="showTrendLines" :entries="props.entries" />

        <UCard>
          <div class="space-y-1">
            <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
              Last catalog import
            </p>
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              {{ props.catalogUpdatedAt }}
            </p>
          </div>
        </UCard>
      </div>
    </template>
  </USlideover>
</template>
