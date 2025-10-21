<script setup lang="ts">
import { computed } from "vue";
import StatCard from "~/components/StatCard.vue";
import { useDateDisplay } from "~/composables/useDateDisplay";
import type { MarketStatsResponse, MarketProgramType } from "~/types";

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
</script>

<template>
  <div class="space-y-8 py-6">
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
              <div class="mt-3 flex flex-wrap gap-2">
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
  </div>
</template>
