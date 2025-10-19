<script setup lang="ts">
import { computed } from "vue";
import type { KevEntrySummary } from "~/types";
import type {
  LatestAdditionSummary,
  SeverityDistributionDatum,
  SourceBadgeMap,
} from "~/types/dashboard";

const props = defineProps<{
  open: boolean;
  isBusy: boolean;
  showRiskDetails: boolean;
  showTrendLines: boolean;
  matchingResultsLabel: string;
  highSeverityShareLabel: string;
  highSeveritySummary: string;
  averageCvssLabel: string;
  averageCvssSummary: string;
  ransomwareShareLabel: string;
  ransomwareSummary: string;
  internetExposedShareLabel: string;
  internetExposedSummary: string;
  severityDistribution: SeverityDistributionDatum[];
  latestAdditionSummaries: LatestAdditionSummary[];
  sourceBadgeMap: SourceBadgeMap;
  catalogUpdatedAt: string;
  entries: KevEntrySummary[];
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "update:show-risk-details", value: boolean): void;
  (event: "update:show-trend-lines", value: boolean): void;
  (event: "open-details", entry: KevEntrySummary): void;
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

const handleOpenDetails = (entry: KevEntrySummary) => {
  emit("open-details", entry);
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
          :matching-results-label="props.matchingResultsLabel"
          :high-severity-share-label="props.highSeverityShareLabel"
          :high-severity-summary="props.highSeveritySummary"
          :average-cvss-label="props.averageCvssLabel"
          :average-cvss-summary="props.averageCvssSummary"
          :ransomware-share-label="props.ransomwareShareLabel"
          :ransomware-summary="props.ransomwareSummary"
          :internet-exposed-share-label="props.internetExposedShareLabel"
          :internet-exposed-summary="props.internetExposedSummary"
          :severity-distribution="props.severityDistribution"
          :latest-addition-summaries="props.latestAdditionSummaries"
          :source-badge-map="props.sourceBadgeMap"
          @open-details="handleOpenDetails"
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
