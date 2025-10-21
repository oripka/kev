<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type {
  ClassificationReviewCategorySet,
  ClassificationReviewIssue,
  ClassificationReviewResponse,
  ClassificationReviewSuccess,
  KevEntrySummary,
} from "~/types";
import type { ActiveFilter } from "~/types/dashboard";

const MAX_SAMPLE_SIZE = 12;
const DEFAULT_SAMPLE_TARGET = 8;
const SAMPLE_CANDIDATES = [3, 5, 8, 10, 12];

const props = defineProps<{
  open: boolean;
  entries: KevEntrySummary[];
  matchingResultsLabel: string;
  activeFilters: ActiveFilter[];
  hasActiveFilters: boolean;
  isBusy: boolean;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
}>();

const open = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const sampleSize = ref<number>(0);

const sampleSizeOptions = computed(() => {
  const total = props.entries.length;
  if (!total) {
    return [] as Array<{ label: string; value: number }>;
  }

  const max = Math.min(MAX_SAMPLE_SIZE, total);
  const options = SAMPLE_CANDIDATES.filter((candidate) => candidate <= max);

  if (!options.length) {
    for (let value = 1; value <= max; value += 1) {
      options.push(value);
      if (options.length >= 5) {
        break;
      }
    }
  }

  if (!options.includes(max)) {
    options.push(max);
  }

  const unique = Array.from(
    new Set(options.filter((value) => value > 0 && value <= max)),
  ).sort((first, second) => first - second);

  return unique.map((value) => ({
    label: value === max ? `First ${value} (max)` : `First ${value}`,
    value,
  }));
});

watch(
  () => props.entries.length,
  () => {
    const total = props.entries.length;
    if (!total) {
      sampleSize.value = 0;
      return;
    }

    const max = Math.min(MAX_SAMPLE_SIZE, total);
    if (!sampleSize.value) {
      sampleSize.value = Math.min(DEFAULT_SAMPLE_TARGET, max);
    } else if (sampleSize.value > max) {
      sampleSize.value = max;
    }
  },
  { immediate: true },
);

const sampleEntries = computed(() => {
  if (!sampleSize.value) {
    return [] as KevEntrySummary[];
  }
  return props.entries.slice(0, sampleSize.value);
});

const selectedEntryIds = computed(() =>
  sampleEntries.value.map((entry) => entry.id),
);

const reviewResult = ref<ClassificationReviewResponse | null>(null);
const reviewError = ref<string | null>(null);
const isReviewing = ref(false);

const reviewSuccess = computed<ClassificationReviewSuccess | null>(() => {
  const result = reviewResult.value;
  if (result && result.status === "ok") {
    return result;
  }
  return null;
});

const usedEntryIds = computed(() => reviewSuccess.value?.usedEntryIds ?? []);
const usedEntrySet = computed(() => new Set(usedEntryIds.value));
const missingEntryIds = computed(() => reviewSuccess.value?.missingEntryIds ?? []);

const canRunReview = computed(
  () =>
    !props.isBusy &&
    !isReviewing.value &&
    selectedEntryIds.value.length > 0,
);

const buildContextPayload = () => {
  const label = props.matchingResultsLabel?.trim();
  const filters = props.activeFilters
    .map((filter) => ({
      key: String(filter.key).trim(),
      label: filter.label.trim(),
      value: filter.value.trim(),
    }))
    .filter((filter) => filter.key && filter.label && filter.value);

  if (!label && !filters.length) {
    return null;
  }

  return {
    ...(label ? { matchingResultsLabel: label } : {}),
    ...(filters.length ? { activeFilters: filters } : {}),
  };
};

const runReview = async () => {
  if (!canRunReview.value) {
    return;
  }

  const entryIds = selectedEntryIds.value;
  if (!entryIds.length) {
    return;
  }

  isReviewing.value = true;
  reviewError.value = null;

  const context = buildContextPayload();

  try {
    const payload = context
      ? { entryIds, context }
      : { entryIds };

    const response = await $fetch<ClassificationReviewResponse>(
      "/api/classification-review",
      {
        method: "POST",
        body: payload,
      },
    );

    reviewResult.value = response;
    if (response.status === "error") {
      reviewError.value = response.message;
    }
  } catch (error) {
    reviewResult.value = null;
    reviewError.value =
      error instanceof Error
        ? error.message
        : "Unexpected error while requesting the audit.";
  } finally {
    isReviewing.value = false;
  }
};

const confidenceColorMap: Record<
  ClassificationReviewIssue["confidence"],
  string
> = {
  low: "neutral",
  medium: "warning",
  high: "emerald",
};

const confidenceLabelMap: Record<
  ClassificationReviewIssue["confidence"],
  string
> = {
  low: "Low confidence",
  medium: "Medium confidence",
  high: "High confidence",
};

const hasOverviewData = computed(
  () =>
    Boolean(
      reviewSuccess.value?.overview.domainCounts.length ||
        reviewSuccess.value?.overview.exploitCounts.length ||
        reviewSuccess.value?.overview.vulnerabilityCounts.length,
    ),
);

const overviewInternetLabel = computed(() => {
  const overview = reviewSuccess.value?.overview;
  if (!overview) {
    return null;
  }

  const { exposed, total } = overview.internetExposure;
  if (!total) {
    return null;
  }

  const percent = Math.round((exposed / total) * 100);
  return `${exposed.toLocaleString()} of ${total.toLocaleString()} entries (${percent}%) marked internet-exposed`;
});

const recommendedHasContent = (categories: ClassificationReviewCategorySet | null) =>
  Boolean(
    categories?.domain?.length ||
      categories?.exploit?.length ||
      categories?.vulnerability?.length ||
      typeof categories?.internetExposed === "boolean",
  );

const formatCategoryBadgeKey = (
  prefix: string,
  entryId: string,
  value: string,
) => `${prefix}-${entryId}-${value}`;

const entryHasBeenReviewed = (entryId: string) =>
  usedEntrySet.value.has(entryId);

const reviewFilters = computed(() => props.activeFilters);
</script>

<template>
  <USlideover
    v-model:open="open"
    title="Classification quality audit"
    description="Send a limited batch of catalog entries to an LLM to validate taxonomy accuracy and suggest heuristics updates."
    :ui="{ content: 'max-w-4xl' }"
    :unmount-on-hide="false"
  >
    <template #body>
      <div class="space-y-6">
        <UCard>
          <div class="space-y-3">
            <div class="flex flex-wrap items-center gap-2 text-sm text-neutral-600 dark:text-neutral-300">
              <span class="font-medium text-neutral-800 dark:text-neutral-100">Visible results:</span>
              <UBadge color="primary" variant="soft" class="font-semibold">
                {{ props.matchingResultsLabel || '—' }}
              </UBadge>
            </div>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
              The audit only reviews the first entries from the current table view to keep token usage predictable.
            </p>
            <div
              v-if="props.hasActiveFilters && reviewFilters.length"
              class="flex flex-wrap gap-2"
            >
              <UBadge
                v-for="filter in reviewFilters"
                :key="`${filter.key}:${filter.value}`"
                color="neutral"
                variant="soft"
                class="text-xs font-medium"
              >
                {{ filter.label }} · {{ filter.value }}
              </UBadge>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="space-y-1">
              <p class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                Sample selection
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                Choose how many rows to audit. The tool caps requests at {{ MAX_SAMPLE_SIZE }} entries.
              </p>
            </div>
          </template>

          <div class="space-y-4">
            <UFormField
              label="Entries to review"
              description="Entries are taken from the top of the current result list."
            >
              <USelectMenu
                v-model="sampleSize"
                :items="sampleSizeOptions"
                value-key="value"
                option-attribute="label"
                :disabled="!sampleSizeOptions.length"
              />
            </UFormField>

            <div class="flex items-center justify-between gap-3 text-sm text-neutral-600 dark:text-neutral-300">
              <span>Selected entries: {{ selectedEntryIds.length }}</span>
              <UButton
                color="primary"
                :disabled="!canRunReview"
                :loading="isReviewing"
                icon="i-lucide-sparkles"
                @click="runReview"
              >
                Run classification audit
              </UButton>
            </div>
          </div>
        </UCard>

        <div>
          <h3 class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
            Entries in scope
          </h3>
          <p class="text-xs text-neutral-500 dark:text-neutral-400">
            Descriptions are trimmed before being sent to the model for cost control.
          </p>

          <div
            v-if="sampleEntries.length"
            class="mt-3 divide-y divide-neutral-200 overflow-hidden rounded-xl border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-neutral-900"
          >
            <div
              v-for="entry in sampleEntries"
              :key="entry.id"
              class="space-y-2 px-4 py-3"
            >
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div class="min-w-0 space-y-1">
                  <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                    {{ entry.cveId }} · {{ entry.vulnerabilityName }}
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ entry.vendor }} · {{ entry.product }}
                  </p>
                </div>
                <UBadge
                  v-if="entryHasBeenReviewed(entry.id)"
                  color="emerald"
                  variant="soft"
                  class="text-[11px] font-semibold"
                >
                  Audited
                </UBadge>
              </div>

              <div class="flex flex-wrap gap-1 text-[11px] font-medium">
                <UBadge
                  v-for="domain in entry.domainCategories"
                  :key="formatCategoryBadgeKey('domain', entry.id, domain)"
                  color="primary"
                  variant="soft"
                >
                  {{ domain }}
                </UBadge>
                <UBadge
                  v-for="layer in entry.exploitLayers"
                  :key="formatCategoryBadgeKey('exploit', entry.id, layer)"
                  color="warning"
                  variant="soft"
                >
                  {{ layer }}
                </UBadge>
                <UBadge
                  v-for="category in entry.vulnerabilityCategories"
                  :key="formatCategoryBadgeKey('vuln', entry.id, category)"
                  color="secondary"
                  variant="soft"
                >
                  {{ category }}
                </UBadge>
              </div>
            </div>
          </div>

          <p
            v-else
            class="mt-3 text-sm text-neutral-500 dark:text-neutral-400"
          >
            No entries match the current filters.
          </p>
        </div>

        <UCard
          v-if="isReviewing"
          class="border-dashed border-primary-200 dark:border-primary-500/60"
        >
          <div class="flex items-center gap-3 text-sm text-neutral-600 dark:text-neutral-300">
            <UIcon name="i-lucide-refresh-cw" class="size-4 animate-spin" />
            <span>Running classification audit…</span>
          </div>
        </UCard>

        <UAlert
          v-if="reviewError"
          color="error"
          variant="soft"
          title="Audit request failed"
          :description="reviewError"
        />

        <template v-if="reviewSuccess">
          <UCard>
            <div class="space-y-3">
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                    Model · {{ reviewSuccess.model }}
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Reviewed {{ reviewSuccess.usedEntryIds.length.toLocaleString() }} of {{ selectedEntryIds.length.toLocaleString() }} selected entries.
                  </p>
                </div>
                <div
                  v-if="reviewSuccess.usage"
                  class="text-right text-xs text-neutral-500 dark:text-neutral-400"
                >
                  <p v-if="reviewSuccess.usage.promptTokens !== undefined">
                    Prompt tokens · {{ reviewSuccess.usage.promptTokens?.toLocaleString() }}
                  </p>
                  <p v-if="reviewSuccess.usage.completionTokens !== undefined">
                    Completion tokens · {{ reviewSuccess.usage.completionTokens?.toLocaleString() }}
                  </p>
                  <p v-if="reviewSuccess.usage.totalTokens !== undefined">
                    Total tokens · {{ reviewSuccess.usage.totalTokens?.toLocaleString() }}
                  </p>
                </div>
              </div>

              <div v-if="hasOverviewData" class="flex flex-wrap gap-2 text-[11px] font-medium">
                <UBadge
                  v-for="domain in reviewSuccess.overview.domainCounts.slice(0, 3)"
                  :key="`overview-domain-${domain.value}`"
                  color="primary"
                  variant="soft"
                >
                  {{ domain.value }} · {{ Math.round(domain.share * 100) }}%
                </UBadge>
                <UBadge
                  v-for="exploit in reviewSuccess.overview.exploitCounts.slice(0, 3)"
                  :key="`overview-exploit-${exploit.value}`"
                  color="warning"
                  variant="soft"
                >
                  {{ exploit.value }} · {{ Math.round(exploit.share * 100) }}%
                </UBadge>
                <UBadge
                  v-for="vuln in reviewSuccess.overview.vulnerabilityCounts.slice(0, 3)"
                  :key="`overview-vuln-${vuln.value}`"
                  color="secondary"
                  variant="soft"
                >
                  {{ vuln.value }} · {{ Math.round(vuln.share * 100) }}%
                </UBadge>
              </div>

              <p
                v-if="overviewInternetLabel"
                class="text-xs text-neutral-500 dark:text-neutral-400"
              >
                {{ overviewInternetLabel }}
              </p>

              <UAlert
                v-if="missingEntryIds.length"
                color="warning"
                variant="soft"
                title="Some entries were unavailable"
              >
                <p class="text-xs">
                  Missing IDs: {{ missingEntryIds.join(", ") }}
                </p>
              </UAlert>
            </div>
          </UCard>

          <div>
            <h3 class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
              Flagged classification issues
            </h3>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
              Review these entries in <code>classification.ts</code> to tighten heuristics or curated hints.
            </p>

            <div
              v-if="!reviewSuccess.issues.length"
              class="mt-3 rounded-lg border border-neutral-200 bg-neutral-50 p-4 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300"
            >
              The model did not flag issues in the sampled entries.
            </div>

            <div v-else class="mt-3 space-y-3">
              <UCard
                v-for="issue in reviewSuccess.issues"
                :key="`${issue.cveId}-${issue.summary}`"
              >
                <div class="space-y-2">
                  <div class="flex items-start justify-between gap-3">
                    <div>
                      <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                        {{ issue.cveId }}
                      </p>
                      <p class="text-sm text-neutral-600 dark:text-neutral-300">
                        {{ issue.summary }}
                      </p>
                    </div>
                    <UBadge
                      :color="confidenceColorMap[issue.confidence]"
                      variant="soft"
                      class="text-[11px] font-semibold"
                    >
                      {{ confidenceLabelMap[issue.confidence] }}
                    </UBadge>
                  </div>

                  <ul
                    v-if="issue.suspectedIssues.length"
                    class="list-inside list-disc text-xs text-neutral-500 dark:text-neutral-400"
                  >
                    <li v-for="item in issue.suspectedIssues" :key="item">
                      {{ item }}
                    </li>
                  </ul>

                  <div
                    v-if="recommendedHasContent(issue.recommendedCategories)"
                    class="space-y-1 text-xs text-neutral-500 dark:text-neutral-400"
                  >
                    <p class="font-medium text-neutral-600 dark:text-neutral-300">
                      Suggested classifications
                    </p>
                    <div class="flex flex-wrap gap-2 text-[11px] font-medium">
                      <template v-if="issue.recommendedCategories?.domain?.length">
                        <UBadge
                          v-for="domain in issue.recommendedCategories.domain"
                          :key="`issue-${issue.cveId}-domain-${domain}`"
                          color="primary"
                          variant="soft"
                        >
                          {{ domain }}
                        </UBadge>
                      </template>
                      <template v-if="issue.recommendedCategories?.exploit?.length">
                        <UBadge
                          v-for="layer in issue.recommendedCategories.exploit"
                          :key="`issue-${issue.cveId}-exploit-${layer}`"
                          color="warning"
                          variant="soft"
                        >
                          {{ layer }}
                        </UBadge>
                      </template>
                      <template v-if="issue.recommendedCategories?.vulnerability?.length">
                        <UBadge
                          v-for="category in issue.recommendedCategories.vulnerability"
                          :key="`issue-${issue.cveId}-vuln-${category}`"
                          color="secondary"
                          variant="soft"
                        >
                          {{ category }}
                        </UBadge>
                      </template>
                      <UBadge
                        v-if="typeof issue.recommendedCategories?.internetExposed === 'boolean'"
                        color="emerald"
                        variant="soft"
                      >
                        Internet exposed ·
                        {{ issue.recommendedCategories?.internetExposed ? 'Yes' : 'No' }}
                      </UBadge>
                    </div>
                  </div>

                  <p
                    v-if="issue.justification"
                    class="text-xs text-neutral-500 dark:text-neutral-400"
                  >
                    {{ issue.justification }}
                  </p>
                </div>
              </UCard>
            </div>
          </div>

          <div>
            <h3 class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
              Curated taxonomy suggestions
            </h3>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
              Add or adjust curated hints in <code>classification.ts</code> using the guidance below.
            </p>

            <div
              v-if="!reviewSuccess.taxonomySuggestions.length"
              class="mt-3 rounded-lg border border-neutral-200 bg-neutral-50 p-4 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300"
            >
              No curated taxonomy changes suggested for this sample.
            </div>

            <div v-else class="mt-3 space-y-3">
              <UCard
                v-for="suggestion in reviewSuccess.taxonomySuggestions"
                :key="`${suggestion.vendorKey ?? 'any'}-${suggestion.productKey}`"
              >
                <div class="space-y-2 text-sm">
                  <p class="font-semibold text-neutral-900 dark:text-neutral-100">
                    {{ suggestion.vendorKey ? `${suggestion.vendorKey} · ${suggestion.productKey}` : suggestion.productKey }}
                  </p>
                  <div class="flex flex-wrap gap-2 text-[11px] font-medium">
                    <UBadge
                      v-for="domain in suggestion.proposedCategories"
                      :key="`suggest-${suggestion.productKey}-category-${domain}`"
                      color="primary"
                      variant="soft"
                    >
                      Base · {{ domain }}
                    </UBadge>
                    <UBadge
                      v-for="domain in suggestion.proposedAddCategories"
                      :key="`suggest-${suggestion.productKey}-add-${domain}`"
                      color="secondary"
                      variant="soft"
                    >
                      Add · {{ domain }}
                    </UBadge>
                    <UBadge
                      v-if="typeof suggestion.internetExposed === 'boolean'"
                      color="emerald"
                      variant="soft"
                    >
                      Internet exposed ·
                      {{ suggestion.internetExposed ? 'Yes' : 'No' }}
                    </UBadge>
                    <UBadge
                      v-if="typeof suggestion.serverBias === 'boolean'"
                      color="warning"
                      variant="soft"
                    >
                      Server bias ·
                      {{ suggestion.serverBias ? 'True' : 'False' }}
                    </UBadge>
                    <UBadge
                      v-if="typeof suggestion.clientBias === 'boolean'"
                      color="warning"
                      variant="outline"
                    >
                      Client bias ·
                      {{ suggestion.clientBias ? 'True' : 'False' }}
                    </UBadge>
                  </div>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ suggestion.rationale }}
                  </p>
                </div>
              </UCard>
            </div>
          </div>

          <div>
            <h3 class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
              Heuristic improvements
            </h3>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
              Incorporate these ideas into the pattern logic or scoring thresholds in <code>classification.ts</code>.
            </p>

            <div
              v-if="!reviewSuccess.heuristicImprovements.length"
              class="mt-3 rounded-lg border border-neutral-200 bg-neutral-50 p-4 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300"
            >
              No heuristic changes recommended for this run.
            </div>

            <div v-else class="mt-3 space-y-3">
              <UCard
                v-for="idea in reviewSuccess.heuristicImprovements"
                :key="`${idea.focusArea}-${idea.description}`"
              >
                <div class="space-y-1 text-sm text-neutral-600 dark:text-neutral-300">
                  <p class="font-semibold text-neutral-900 dark:text-neutral-100">
                    {{ idea.focusArea }}
                  </p>
                  <p>{{ idea.description }}</p>
                  <p v-if="idea.justification" class="text-xs text-neutral-500 dark:text-neutral-400">
                    {{ idea.justification }}
                  </p>
                </div>
              </UCard>
            </div>
          </div>

          <div v-if="reviewSuccess.generalRecommendations.length">
            <h3 class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
              General recommendations
            </h3>
            <ul class="mt-2 list-disc space-y-1 pl-5 text-sm text-neutral-600 dark:text-neutral-300">
              <li v-for="item in reviewSuccess.generalRecommendations" :key="item">
                {{ item }}
              </li>
            </ul>
          </div>

          <UAccordion
            v-if="reviewSuccess.rawResponseSnippet"
            :items="[{ label: 'Raw model response', slot: 'raw' }]"
            size="sm"
          >
            <template #raw>
              <pre class="max-h-64 overflow-auto rounded-lg bg-neutral-900 p-4 text-xs text-neutral-100 dark:bg-neutral-950">
{{ reviewSuccess.rawResponseSnippet }}
              </pre>
            </template>
          </UAccordion>
        </template>
      </div>
    </template>
  </USlideover>
</template>
