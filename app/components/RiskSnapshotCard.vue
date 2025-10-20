<script setup lang="ts">
import { computed } from "vue";
import type { KevEntrySummary } from "~/types";

type SeverityDistributionDatum = {
  key: string;
  label: string;
  color: string;
  count: number;
  percent: number;
  percentLabel: string;
};

type LatestAdditionSummary = {
  entry: KevEntrySummary;
  dateLabel: string;
  vendorProduct: string;
  wellKnown: string | null;
  sources: KevEntrySummary["sources"];
  internetExposed: boolean;
};

type SourceBadgeMap = Record<
  KevEntrySummary["sources"][number],
  { label: string; color: string }
>;

const props = defineProps<{
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
  showRiskDetails: boolean;
}>();

const emit = defineEmits<{
  (event: "update:show-risk-details", value: boolean): void;
  (event: "open-details", entry: KevEntrySummary): void;
}>();

const riskDetails = computed({
  get: () => props.showRiskDetails,
  set: (value: boolean) => emit("update:show-risk-details", value),
});

const openDetails = (entry: KevEntrySummary) => {
  emit("open-details", entry);
};
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
        <UBadge color="primary" variant="soft" class="text-sm font-semibold">
          {{ props.matchingResultsLabel }} matching exploits
        </UBadge>
      </div>
    </template>

    <div class="space-y-6">
      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            High &amp; critical share
          </p>
          <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
            {{ props.highSeverityShareLabel }}
          </p>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.highSeveritySummary }}
          </p>
        </div>
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Average CVSS
          </p>
          <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
            {{ props.averageCvssLabel }}
          </p>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.averageCvssSummary }}
          </p>
        </div>
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Ransomware-linked CVEs
          </p>
          <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
            {{ props.ransomwareShareLabel }}
          </p>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            {{ props.ransomwareSummary }}
          </p>
        </div>
        <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Internet exposure share
          </p>
          <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
            {{ props.internetExposedShareLabel }}
          </p>
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
                <div class="flex items-center justify-between gap-3">
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
                <div v-if="props.latestAdditionSummaries.length" class="space-y-3">
                  <div
                    v-for="item in props.latestAdditionSummaries"
                    :key="item.entry.cveId"
                    class="space-y-3 rounded-lg border border-neutral-200 bg-white/80 p-3 dark:border-neutral-800 dark:bg-neutral-900/60"
                  >
                    <div class="flex items-center justify-between gap-3">
                      <div class="space-y-1">
                        <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                          {{ item.entry.vulnerabilityName }}
                        </p>
                        <p v-if="item.wellKnown" class="text-xs font-medium text-primary-600 dark:text-primary-400">
                          {{ item.wellKnown }}
                        </p>
                        <p class="text-xs text-neutral-500 dark:text-neutral-400">
                          {{ item.vendorProduct }}
                        </p>
                      </div>
                      <UBadge color="primary" variant="soft" class="text-xs font-semibold">
                        {{ item.dateLabel }}
                      </UBadge>
                    </div>

                    <div class="flex flex-wrap items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
                      <UBadge color="neutral" variant="soft" class="font-semibold">
                        {{ item.entry.cveId }}
                      </UBadge>
                      <UBadge
                        v-if="item.internetExposed"
                        color="warning"
                        variant="soft"
                        class="font-semibold"
                      >
                        Internet-exposed
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

                    <div class="flex justify-end">
                      <UButton
                        color="neutral"
                        variant="ghost"
                        size="xs"
                        icon="i-lucide-eye"
                        @click="openDetails(item.entry)"
                      >
                        View details
                      </UButton>
                    </div>
                  </div>
                </div>
                <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
                  No entries match the current filters yet.
                </p>
              </div>
            </div>
          </div>
        </template>
      </UCollapsible>
    </div>
  </UCard>
</template>
