<script setup lang="ts">
import { computed } from "vue";
import type { FocusTopic } from "~/constants/focusTopics";
import { useKevData } from "~/composables/useKevData";

const props = defineProps<{
  topic: FocusTopic;
  badgeColor: string;
  badgeLabel: string;
}>();

const defaultSources = "kev,enisa,historic,metasploit,poc";

const formatDate = (input: Date): string => input.toISOString().split("T")[0];

const now = new Date();
const fiveYearDate = new Date(now);
fiveYearDate.setFullYear(now.getFullYear() - 5);
const fiveYearCutoff = formatDate(fiveYearDate);

const baseQuery = computed(() => ({
  ...props.topic.filters,
  sources: props.topic.filters.sources ?? defaultSources,
  fromDate: fiveYearCutoff,
  limit: 3,
  sort: "publicationDate",
  sortDirection: "desc",
  includeMarketSignals: false,
}));

const { entries, totalEntries, pending } = useKevData(baseQuery);

const formattedTotal = computed(() =>
  new Intl.NumberFormat("en-US").format(totalEntries.value || 0),
);

const sampleEntries = computed(() => entries.value.slice(0, 3));

const hasSampleEntries = computed(() => sampleEntries.value.length > 0);

const sampleLabel = (index: number) => `sample-cve-${props.topic.slug}-${index}`;
</script>

<template>
  <UCard
    v-bind="$attrs"
    class="group relative flex h-full flex-col overflow-hidden border border-neutral-200/70 bg-white/95 shadow-sm transition hover:-translate-y-0.5 hover:border-primary-300/80 hover:shadow-lg dark:border-neutral-800/70 dark:bg-neutral-900/90 dark:hover:border-primary-400/70 dark:hover:shadow-[0_16px_30px_rgba(80,135,255,0.18)]"
  >
    <div
      class="pointer-events-none absolute inset-0 bg-gradient-to-br from-primary-100/20 via-transparent to-transparent opacity-0 transition group-hover:opacity-100 dark:from-primary-500/12"
      aria-hidden="true"
    />
    <div class="relative z-10 flex h-full flex-col gap-5">
      <div class="flex items-center justify-between gap-3">
        <UBadge :color="badgeColor" variant="soft" class="font-semibold shadow-sm">
          {{ badgeLabel }}
        </UBadge>
        <span
          class="rounded-full bg-primary-500/10 px-3 py-1 text-xs font-semibold text-primary-600 shadow-sm transition group-hover:bg-primary-500/15 dark:bg-primary-500/15 dark:text-primary-200 dark:group-hover:bg-primary-500/25"
        >
          5-year lens
        </span>
      </div>

      <div class="space-y-2">
        <h3 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">
          {{ topic.title }}
        </h3>
        <p class="text-sm leading-relaxed text-neutral-600 dark:text-neutral-300">
          {{ topic.summary }}
        </p>
      </div>

      <div
        class="min-h-[200px] rounded-xl bg-gradient-to-br from-primary-100/70 via-primary-50/60 to-primary-50/20 p-4 shadow-inner transition group-hover:from-primary-100/80 group-hover:via-primary-50 dark:from-primary-500/20 dark:via-primary-500/12 dark:to-primary-500/8 dark:group-hover:from-primary-500/22"
      >
        <p class="text-xs font-semibold uppercase tracking-wide text-primary-600 dark:text-primary-200">
          Documented exploits · last five years
        </p>
        <div class="mt-3 flex items-baseline gap-2">
          <USkeleton v-if="pending" class="h-8 w-20 rounded-md" />
          <span v-else class="text-3xl font-bold text-primary-700 dark:text-primary-100">
            {{ formattedTotal }}
          </span>
          <span class="text-sm text-neutral-500 dark:text-neutral-400">
            confirmed entries
          </span>
        </div>
        <ul
          v-if="hasSampleEntries"
          class="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-300"
        >
          <li
            v-for="(entry, entryIndex) in sampleEntries"
            :key="entry.id || sampleLabel(entryIndex)"
            class="flex items-start gap-2 rounded-lg bg-white/90 px-3 py-2 text-left shadow-sm ring-1 ring-primary-100/40 transition group-hover:ring-primary-200/60 dark:bg-neutral-900/70 dark:ring-neutral-700/60 dark:group-hover:bg-neutral-900/80 dark:group-hover:ring-primary-500/40"
          >
            <span class="font-semibold text-primary-600 dark:text-primary-200">
              {{ entry.cveId }}
            </span>
            <span class="text-neutral-500 dark:text-neutral-400">
              {{ entry.product || entry.vendor }}
            </span>
          </li>
        </ul>
        <p v-else-if="!pending" class="mt-4 text-xs text-neutral-500 dark:text-neutral-400">
          No recent exploit activity recorded in this window.
        </p>
      </div>

      <div class="mt-auto">
        <ul
          v-if="topic.highlightNotes?.length"
          class="list-disc space-y-1 pl-5 text-xs text-neutral-500 dark:text-neutral-400"
        >
          <li v-for="note in topic.highlightNotes" :key="note">
            {{ note }}
          </li>
        </ul>
      </div>
    </div>
  </UCard>
</template>
