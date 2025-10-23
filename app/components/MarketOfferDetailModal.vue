<script setup lang="ts">
import { computed } from "vue";
import { useDateDisplay } from "~/composables/useDateDisplay";
import type {
  CvssSeverity,
  MarketOfferCategoryTag,
  MarketOfferListItem,
  MarketOfferTargetMatchMethod,
  MarketProgramType,
} from "~/types";

const props = defineProps<{
  open: boolean;
  offer: MarketOfferListItem | null;
}>();

const emit = defineEmits<{ (event: "update:open", value: boolean): void }>();

const isOpen = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

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

const formatCategoryTypeLabel = (value: string) =>
  value
    .split(/[-_\s]+/u)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const matchMethodLabels: Record<MarketOfferTargetMatchMethod, string> = {
  exact: "Exact catalog match",
  fuzzy: "Fuzzy catalog match",
  "manual-review": "Manual review mapping",
  unknown: "Match method unknown",
};

const matchMethodColors: Record<MarketOfferTargetMatchMethod, string> = {
  exact: "success",
  fuzzy: "warning",
  "manual-review": "neutral",
  unknown: "neutral",
};

const cvssSeverityColors: Record<CvssSeverity, string> = {
  None: "success",
  Low: "primary",
  Medium: "warning",
  High: "error",
  Critical: "error",
};

const buildCvssLabel = (severity: CvssSeverity | null, score: number | null) => {
  const parts: string[] = [];

  if (severity) {
    parts.push(severity);
  }

  if (typeof score === "number" && Number.isFinite(score)) {
    parts.push(score.toFixed(1));
  }

  if (!parts.length) {
    parts.push("Unknown");
  }

  return parts.join(" ");
};

const offer = computed(() => props.offer);

const rewardRangeLabel = computed(() => {
  const current = offer.value;
  if (!current) {
    return "—";
  }

  const { minRewardUsd, maxRewardUsd } = current;
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
});

const averageRewardLabel = computed(() => {
  const value = offer.value?.averageRewardUsd;
  return typeof value === "number" ? currencyFormatter.format(value) : null;
});

const lastCapturedLabel = computed(() => {
  const timestamp = offer.value?.sourceCaptureDate;
  return timestamp
    ? formatDate(timestamp, { fallback: timestamp, preserveInputOnError: true })
    : "Not available";
});

const matchedKevCount = computed(() => offer.value?.matchedKevCveIds.length ?? 0);

const groupedCategories = computed(() => {
  const categories = offer.value?.categories ?? [];
  const groups = new Map<string, MarketOfferCategoryTag[]>();

  for (const category of categories) {
    const existing = groups.get(category.type) ?? [];
    existing.push(category);
    groups.set(category.type, existing);
  }

  return Array.from(groups.entries()).map(([type, items]) => ({
    type,
    label: formatCategoryTypeLabel(type),
    items,
  }));
});

const targets = computed(() => offer.value?.targets ?? []);
</script>

<template>
  <UModal
    v-model:open="isOpen"
    :ui="{
      content: 'w-full max-w-4xl rounded-xl shadow-lg',
      body: 'p-0',
    }"
  >
    <template #body>
      <div v-if="offer" class="space-y-6">
        <div class="border-b border-neutral-200 px-6 py-5 dark:border-neutral-800">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="space-y-2">
              <div class="flex flex-wrap items-center gap-2">
                <UBadge
                  color="info"
                  variant="soft"
                  class="text-[11px] font-semibold"
                >
                  {{ formatProgramTypeLabel(offer.programType) }}
                </UBadge>
                <UBadge
                  v-if="matchedKevCount"
                  color="warning"
                  variant="soft"
                  class="text-[11px] font-semibold"
                >
                  {{ matchedKevCount.toLocaleString() }} KEV matches
                </UBadge>
              </div>
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                {{ offer.title }}
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                {{ offer.programName }}
              </p>
              <p
                v-if="offer.description"
                class="max-w-3xl text-sm text-neutral-600 dark:text-neutral-300"
              >
                {{ offer.description }}
              </p>
            </div>
            <div class="space-y-2 text-right text-sm text-neutral-500 dark:text-neutral-400">
              <p>
                Last captured
                <span class="font-medium text-neutral-800 dark:text-neutral-200">
                  {{ lastCapturedLabel }}
                </span>
              </p>
              <ULink
                v-if="offer.sourceUrl"
                :href="offer.sourceUrl"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex items-center gap-2 text-sm font-medium text-primary-600 transition hover:text-primary-500 dark:text-primary-300"
              >
                View source
                <UIcon name="i-lucide-arrow-up-right" class="size-4" />
              </ULink>
            </div>
          </div>
        </div>

        <div class="space-y-6 px-6 pb-6">
          <section class="space-y-3">
            <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              Reward signals
            </p>
            <div class="flex flex-wrap gap-3">
              <div class="min-w-[160px] rounded-lg border border-neutral-200 px-4 py-3 dark:border-neutral-800">
                <p class="text-xs uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Range
                </p>
                <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ rewardRangeLabel }}
                </p>
                <p
                  v-if="averageRewardLabel"
                  class="text-xs text-neutral-500 dark:text-neutral-400"
                >
                  Average {{ averageRewardLabel }}
                </p>
              </div>
              <div
                v-if="offer.exclusivity"
                class="min-w-[160px] rounded-lg border border-neutral-200 px-4 py-3 dark:border-neutral-800"
              >
                <p class="text-xs uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Exclusivity
                </p>
                <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
                  {{ offer.exclusivity }}
                </p>
              </div>
            </div>
          </section>

          <section v-if="groupedCategories.length" class="space-y-3">
            <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              Leading categories
            </p>
            <div class="space-y-2">
              <div
                v-for="group in groupedCategories"
                :key="group.type"
                class="space-y-1"
              >
                <p class="text-[11px] font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  {{ group.label }}
                </p>
                <div class="flex flex-wrap gap-2">
                  <UBadge
                    v-for="category in group.items"
                    :key="`${group.type}-${category.key}`"
                    color="neutral"
                    variant="soft"
                    class="text-xs"
                  >
                    {{ category.name }}
                  </UBadge>
                </div>
              </div>
            </div>
          </section>

          <section class="space-y-3">
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                Target coverage
              </p>
              <span class="text-xs text-neutral-500 dark:text-neutral-400">
                {{ targets.length.toLocaleString() }} mapped
                {{ targets.length === 1 ? 'target' : 'targets' }}
              </span>
            </div>

            <div v-if="targets.length" class="space-y-4">
              <div
                v-for="target in targets"
                :key="`${target.vendorKey}-${target.productKey}`"
                class="space-y-3 rounded-lg border border-neutral-200 p-4 dark:border-neutral-800"
              >
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div class="space-y-1">
                    <p class="text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                      {{ target.vendorName }} · {{ target.productName }}
                    </p>
                    <p
                      v-if="target.cveId"
                      class="text-xs text-neutral-500 dark:text-neutral-400"
                    >
                      Reported CVE {{ target.cveId }}
                    </p>
                  </div>
                  <div class="flex flex-wrap gap-2">
                    <UBadge
                      :color="matchMethodColors[target.matchMethod]"
                      variant="soft"
                      class="text-[11px] font-semibold"
                    >
                      {{ matchMethodLabels[target.matchMethod] }}
                    </UBadge>
                    <UBadge
                      v-if="typeof target.confidence === 'number'"
                      color="neutral"
                      variant="soft"
                      class="text-[11px] font-semibold"
                    >
                      Confidence {{ target.confidence }}%
                    </UBadge>
                  </div>
                </div>

                <div v-if="target.matches.length" class="space-y-3">
                  <div
                    v-for="match in target.matches"
                    :key="match.cveId"
                    class="space-y-2 rounded-md bg-neutral-50 p-3 dark:bg-neutral-800/60"
                  >
                    <div class="flex flex-wrap items-center gap-2">
                      <ULink
                        :to="{ path: '/', query: { search: match.cveId } }"
                        class="inline-flex items-center justify-center"
                        :aria-label="`Open catalog with ${match.cveId}`"
                      >
                        <UBadge
                          color="error"
                          variant="soft"
                          class="text-xs font-semibold"
                        >
                          {{ match.cveId }}
                        </UBadge>
                      </ULink>
                      <span class="text-xs font-medium text-neutral-700 dark:text-neutral-200">
                        {{ match.vulnerabilityName }}
                      </span>
                      <UBadge
                        v-if="match.cvssSeverity || typeof match.cvssScore === 'number'"
                        :color="cvssSeverityColors[match.cvssSeverity ?? 'None'] ?? 'neutral'"
                        variant="soft"
                        class="text-[11px] font-semibold"
                      >
                        {{ buildCvssLabel(match.cvssSeverity, match.cvssScore) }}
                      </UBadge>
                    </div>
                    <p
                      v-if="match.vendorKey !== target.vendorKey || match.productKey !== target.productKey"
                      class="text-[11px] text-neutral-500 dark:text-neutral-400"
                    >
                      Catalog entry: {{ match.vendorName }} · {{ match.productName }}
                    </p>
                    <code
                      v-if="match.cvssVector"
                      class="block max-w-full overflow-x-auto rounded bg-neutral-100 px-2 py-1 text-[11px] text-neutral-600 dark:bg-neutral-900 dark:text-neutral-300"
                    >
                      {{ match.cvssVector }}
                    </code>
                    <div v-if="match.domainCategories.length" class="space-y-1">
                      <p class="text-[11px] font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                        Domain
                      </p>
                      <div class="flex flex-wrap gap-1">
                        <UBadge
                          v-for="category in match.domainCategories"
                          :key="`domain-${match.cveId}-${category}`"
                          color="primary"
                          variant="soft"
                          class="text-[11px] font-semibold"
                        >
                          {{ category }}
                        </UBadge>
                      </div>
                    </div>
                    <div v-if="match.exploitLayers.length" class="space-y-1">
                      <p class="text-[11px] font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                        Exploit dynamics
                      </p>
                      <div class="flex flex-wrap gap-1">
                        <UBadge
                          v-for="layer in match.exploitLayers"
                          :key="`layer-${match.cveId}-${layer}`"
                          color="warning"
                          variant="soft"
                          class="text-[11px] font-semibold"
                        >
                          {{ layer }}
                        </UBadge>
                      </div>
                    </div>
                    <div v-if="match.vulnerabilityCategories.length" class="space-y-1">
                      <p class="text-[11px] font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                        Vulnerability mix
                      </p>
                      <div class="flex flex-wrap gap-1">
                        <UBadge
                          v-for="category in match.vulnerabilityCategories"
                          :key="`vuln-${match.cveId}-${category}`"
                          color="secondary"
                          variant="soft"
                          class="text-[11px] font-semibold"
                        >
                          {{ category }}
                        </UBadge>
                      </div>
                    </div>
                  </div>
                </div>
                <p
                  v-else
                  class="text-sm text-neutral-500 dark:text-neutral-400"
                >
                  No catalog matches yet for this target.
                </p>
              </div>
            </div>
            <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
              No mapped targets are available for this offer.
            </p>
          </section>
        </div>
      </div>
      <div v-else class="px-6 py-10 text-center text-sm text-neutral-500 dark:text-neutral-400">
        No offer selected.
      </div>
    </template>
  </UModal>
</template>
