<script setup lang="ts">
type FilterState = {
  domain: string | null;
  exploit: string | null;
  vulnerability: string | null;
  vendor: string | null;
  product: string | null;
};

type ProgressDatum = {
  key: string;
  name: string;
  count: number;
  percent: number;
  percentLabel: string;
};

const props = defineProps<{
  filters: FilterState;
  domainStats: ProgressDatum[];
  exploitLayerStats: ProgressDatum[];
  vulnerabilityStats: ProgressDatum[];
  domainTotalCount: number;
  exploitLayerTotalCount: number;
  vulnerabilityTotalCount: number;
  topDomainStat: ProgressDatum | null;
  topExploitLayerStat: ProgressDatum | null;
  topVulnerabilityStat: ProgressDatum | null;
}>();

const emit = defineEmits<{
  (event: "toggle-filter", key: "domain" | "exploit" | "vulnerability", value: string): void;
}>();

const toggle = (key: "domain" | "exploit" | "vulnerability", value: string) => {
  emit("toggle-filter", key, value);
};
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-col gap-1">
        <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
          Category insights
        </p>
        <p class="text-sm text-neutral-500 dark:text-neutral-400">
          Compare how the filtered vulnerabilities distribute across domains and categories
        </p>
      </div>
    </template>

    <div class="grid gap-6 lg:grid-cols-3">
      <div class="space-y-4">
        <div class="flex items-start justify-between gap-3">
          <div class="space-y-1">
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Domain coverage
            </p>
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Share of vulnerabilities per domain grouping
            </p>
          </div>
          <UBadge color="primary" variant="soft">
            {{ props.domainTotalCount }}
          </UBadge>
        </div>

        <div v-if="props.domainStats.length" class="space-y-3">
          <button
            v-for="stat in props.domainStats"
            :key="stat.key"
            type="button"
            @click="toggle('domain', stat.key)"
            :aria-pressed="props.filters.domain === stat.key"
            :class="[
              'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 dark:focus-visible:ring-emerald-600',
              props.filters.domain === stat.name
                ? 'bg-emerald-50 dark:bg-emerald-500/10 ring-emerald-200 dark:ring-emerald-500/40'
                : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
            ]"
          >
            <div class="flex items-center justify-between gap-3 text-sm">
              <span
                :class="[
                  'truncate font-medium',
                  props.filters.domain === stat.key
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-neutral-900 dark:text-neutral-50',
                ]"
              >
                {{ stat.name }}
              </span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                {{ stat.count }} · {{ stat.percentLabel }}%
              </span>
            </div>
            <UProgress :model-value="stat.percent" :max="100" color="primary" size="sm" />
          </button>
        </div>
        <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
          No domain category data for this filter.
        </p>

        <div v-if="props.topDomainStat" class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
          <span>Top domain</span>
          <span class="font-medium text-neutral-900 dark:text-neutral-50">
            {{ props.topDomainStat.name }} ({{ props.topDomainStat.percentLabel }}%)
          </span>
        </div>
      </div>

      <div class="space-y-4">
        <div class="flex items-start justify-between gap-3">
          <div class="space-y-1">
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Exploit dynamics
            </p>
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              How execution paths cluster for these CVEs
            </p>
          </div>
          <UBadge color="warning" variant="soft">
            {{ props.exploitLayerTotalCount }}
          </UBadge>
        </div>

        <div v-if="props.exploitLayerStats.length" class="space-y-3">
          <button
            v-for="stat in props.exploitLayerStats"
            :key="stat.key"
            type="button"
            @click="toggle('exploit', stat.key)"
            :aria-pressed="props.filters.exploit === stat.key"
            :class="[
              'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 dark:focus-visible:ring-amber-600',
              props.filters.exploit === stat.name
                ? 'bg-amber-50 dark:bg-amber-500/10 ring-amber-200 dark:ring-amber-500/40'
                : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
            ]"
          >
            <div class="flex items-center justify-between gap-3 text-sm">
              <span
                :class="[
                  'truncate font-medium',
                  props.filters.exploit === stat.key
                    ? 'text-amber-600 dark:text-amber-400'
                    : 'text-neutral-900 dark:text-neutral-50',
                ]"
              >
                {{ stat.name }}
              </span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                {{ stat.count }} · {{ stat.percentLabel }}%
              </span>
            </div>
            <UProgress :model-value="stat.percent" :max="100" color="warning" size="sm" />
          </button>
        </div>
        <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
          No exploit profile data for this filter.
        </p>

        <div v-if="props.topExploitLayerStat" class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
          <span>Top profile</span>
          <span class="font-medium text-neutral-900 dark:text-neutral-50">
            {{ props.topExploitLayerStat.name }} ({{ props.topExploitLayerStat.percentLabel }}%)
          </span>
        </div>
      </div>

      <div class="space-y-4">
        <div class="flex items-start justify-between gap-3">
          <div class="space-y-1">
            <p class="text-base font-semibold text-neutral-900 dark:text-neutral-50">
              Vulnerability mix
            </p>
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
              Breakdown of vulnerability categories in view
            </p>
          </div>
          <UBadge color="violet" variant="soft">
            {{ props.vulnerabilityTotalCount }}
          </UBadge>
        </div>

        <div v-if="props.vulnerabilityStats.length" class="space-y-3">
          <button
            v-for="stat in props.vulnerabilityStats"
            :key="stat.key"
            type="button"
            @click="toggle('vulnerability', stat.key)"
            :aria-pressed="props.filters.vulnerability === stat.key"
            :class="[
              'w-full cursor-pointer space-y-2 rounded-lg px-3 py-2 text-left ring-1 ring-transparent transition focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400 dark:focus-visible:ring-rose-600',
              props.filters.vulnerability === stat.key
                ? 'bg-rose-50 dark:bg-rose-500/10 ring-rose-200 dark:ring-rose-500/40'
                : 'bg-transparent hover:bg-neutral-50 cursor-pointer dark:hover:bg-neutral-800/60',
            ]"
          >
            <div class="flex items-center justify-between gap-3 text-sm">
              <span class="truncate font-medium text-neutral-900 dark:text-neutral-50">
                {{ stat.name }}
              </span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                {{ stat.count }} · {{ stat.percentLabel }}%
              </span>
            </div>
            <UProgress :model-value="stat.percent" :max="100" color="error" size="sm" />
          </button>
        </div>
        <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
          No vulnerability category data for this filter.
        </p>

        <div v-if="props.topVulnerabilityStat" class="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
          <span>Top category</span>
          <span class="font-medium text-neutral-900 dark:text-neutral-50">
            {{ props.topVulnerabilityStat.name }} ({{ props.topVulnerabilityStat.percentLabel }}%)
          </span>
        </div>
      </div>
    </div>
  </UCard>
</template>
