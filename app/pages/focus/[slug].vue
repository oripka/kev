<script setup lang="ts">
import { computed } from "vue";
import { createError, useHead, useRoute } from "#imports";
import { focusTopics, type FocusTopic } from "~/constants/focusTopics";
import { computeFocusMetric } from "~/utils/focusMetrics";
import { useKevData } from "~/composables/useKevData";
import { useDateDisplay } from "~/composables/useDateDisplay";

const route = useRoute();
const slug = computed(() => String(route.params.slug ?? ""));

const resolvedTopic = computed<FocusTopic | null>(() =>
  focusTopics.find((topic) => topic.slug === slug.value) ?? null,
);

if (!resolvedTopic.value) {
  throw createError({ statusCode: 404, statusMessage: "Focus topic not found" });
}

const topic = resolvedTopic.value;

useHead({
  title: `${topic.title} · Focus page`,
  meta: [
    {
      name: "description",
      content: topic.summary,
    },
  ],
});

const baseQuery = computed(() => ({
  ...topic.filters,
  sources: topic.filters.sources ?? "kev,enisa,historic,metasploit,poc",
  limit: 10_000,
  sort: "publicationDate",
  sortDirection: "desc",
}));

const {
  entries,
  counts,
  totalEntries,
  timeline,
  pending,
  error,
  refresh,
  updatedAt,
} = useKevData(baseQuery);

const timelinePeriod = computed(() => topic.timelinePeriod ?? "monthly");
const timelineRange = computed(() => timeline.value.range ?? null);
const timelineBuckets = computed(() => timeline.value.buckets?.[timelinePeriod.value] ?? []);
const showTimeline = computed(() => Boolean(timelineRange.value && timelineBuckets.value.length));

const metricResults = computed(() =>
  topic.metrics.map((definition) => ({
    definition,
    result: computeFocusMetric(definition.key, {
      entries: entries.value,
      timeline: timeline.value,
      totalEntries: totalEntries.value,
    }),
  })),
);

const normaliseQueryValue = (value: string | number | boolean): string => {
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  return String(value);
};

const baseCatalogQuery = computed<Record<string, string>>(() => {
  const query: Record<string, string> = {};
  for (const [key, raw] of Object.entries(topic.filters)) {
    if (raw === undefined || raw === null) {
      continue;
    }
    query[key] = normaliseQueryValue(raw);
  }
  query.limit = "10000";
  query.sort = "publicationDate";
  query.sortDirection = "desc";
  return query;
});

const shortcutLinks = computed(() =>
  topic.shortcuts.map((shortcut) => {
    const query = { ...baseCatalogQuery.value };
    for (const [key, raw] of Object.entries(shortcut.query)) {
      if (raw === undefined || raw === null) {
        delete query[key];
        continue;
      }
      query[key] = normaliseQueryValue(raw);
    }
    return { ...shortcut, query };
  }),
);

const topVendors = computed(() => counts.value.vendor.slice(0, 5));
const topProducts = computed(() => counts.value.product.slice(0, 5));
const topExploitLayers = computed(() => counts.value.exploit.slice(0, 5));
const topVulnerabilities = computed(() => counts.value.vulnerability.slice(0, 5));

const { formatRelativeDate } = useDateDisplay();
const lastUpdatedLabel = computed(() =>
  updatedAt.value
    ? formatRelativeDate(updatedAt.value, { fallback: "No imports yet" })
    : "No imports yet",
);

const buildShareUrl = () => {
  if (typeof window === "undefined") {
    return `/focus/${topic.slug}`;
  }
  return window.location.href;
};

const downloadFocusCsv = () => {
  if (typeof window === "undefined" || !entries.value.length) {
    return;
  }

  const rows = entries.value.map((entry) => [
    entry.cveId,
    entry.vendor,
    entry.product,
    entry.cvssSeverity ?? "Unknown",
    entry.cvssScore ?? "",
    entry.dateAdded,
    entry.datePublished ?? "",
    entry.ransomwareUse ?? "",
  ]);

  const header = [
    "CVE",
    "Vendor",
    "Product",
    "CVSS Severity",
    "CVSS Score",
    "Date added",
    "Date published",
    "Ransomware notes",
  ];

  const serialise = (value: unknown) => {
    if (value === null || value === undefined) {
      return "";
    }
    const stringValue = String(value).replace(/"/g, '""');
    if (stringValue.includes(",") || stringValue.includes("\n")) {
      return `"${stringValue}"`;
    }
    return stringValue;
  };

  const csv = [header, ...rows]
    .map((row) => row.map(serialise).join(","))
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${topic.slug}-focus.csv`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};

const sendToTicketing = () => {
  if (typeof window === "undefined") {
    return;
  }

  const url = buildShareUrl();
  const topCves = entries.value
    .slice(0, 5)
    .map((entry) => {
      const context = entry.vulnerabilityName || entry.description || "";
      return `- ${entry.cveId}: ${context}`.trim();
    })
    .join("\n");

  const body = `Focus page: ${url}\n\nTop CVEs to review:\n${topCves}`;
  const subject = `[KEV] ${topic.title} focus follow-up`;
  const mailto = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.open(mailto, "_blank");
};

const copyShareLink = async () => {
  if (typeof window === "undefined" || !navigator.clipboard) {
    return;
  }

  await navigator.clipboard.writeText(buildShareUrl());
};
</script>

<template>
  <UContainer class="py-12 space-y-12">
    <section class="space-y-6">
      <div class="flex flex-wrap items-center gap-3">
        <UBadge
          :color="topic.category === 'critical' ? 'rose' : 'primary'"
          variant="soft"
          class="font-semibold"
        >
          {{ topic.category === "critical" ? "Critical focus" : "Focus" }}
        </UBadge>
        <UBadge v-if="topic.recommendedOwners?.length" color="neutral" variant="subtle">
          Owners: {{ topic.recommendedOwners.join(", ") }}
        </UBadge>
      </div>
      <div class="space-y-3">
        <p v-if="topic.hero.kicker" class="text-sm font-semibold uppercase text-primary-600 dark:text-primary-300">
          {{ topic.hero.kicker }}
        </p>
        <h1 class="text-3xl font-bold text-neutral-900 dark:text-neutral-50">
          {{ topic.headline }}
        </h1>
        <p class="text-base text-neutral-600 dark:text-neutral-300">
          {{ topic.summary }}
        </p>
        <p class="text-sm text-neutral-500 dark:text-neutral-400">
          {{ topic.hero.description }}
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-3 text-xs text-neutral-500 dark:text-neutral-400">
        <span>Last updated {{ lastUpdatedLabel }}</span>
        <UButton size="xs" color="primary" variant="soft" @click="refresh">Refresh data</UButton>
        <UButton size="xs" color="neutral" variant="soft" @click="copyShareLink">Copy share link</UButton>
        <UButton size="xs" color="primary" variant="outline" @click="downloadFocusCsv">
          Export list
        </UButton>
        <UButton size="xs" color="primary" variant="ghost" @click="sendToTicketing">
          Send to ticketing
        </UButton>
      </div>
    </section>

    <UAlert v-if="error" color="rose" variant="soft">
      <template #title>Unable to load focus data</template>
      <template #description>{{ error.message }}</template>
    </UAlert>

    <section v-if="metricResults.length" class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Key signals</h2>
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <FocusMetricCard
          v-for="metric in metricResults"
          :key="metric.definition.key"
          :label="metric.definition.label"
          :value="metric.result.value"
          :caption="metric.result.caption"
          :description="metric.definition.description"
        />
      </div>
      <ul
        v-if="topic.keySignalNotes?.length"
        class="list-disc space-y-1 pl-5 text-xs text-neutral-500 dark:text-neutral-400"
      >
        <li v-for="note in topic.keySignalNotes" :key="note">
          {{ note }}
        </li>
      </ul>
    </section>

    <section v-if="topic.narratives.length" class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Narrative context</h2>
      <div class="grid gap-4 md:grid-cols-2">
        <UCard v-for="item in topic.narratives" :key="item.title">
          <div class="space-y-2">
            <h3 class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
              {{ item.title }}
            </h3>
            <p class="text-sm text-neutral-600 dark:text-neutral-300">
              {{ item.body }}
            </p>
          </div>
        </UCard>
      </div>
    </section>

    <section v-if="showTimeline" class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Exploit cadence</h2>
      <CatalogTimelineCard
        v-if="showTimeline"
        :period="timelinePeriod"
        :range="timelineRange"
        :buckets="timelineBuckets"
      />
    </section>

    <section class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Catalog shortcuts</h2>
      <div class="flex flex-wrap gap-2">
        <ULink
          v-for="shortcut in shortcutLinks"
          :key="shortcut.label"
          :to="{ path: '/', query: shortcut.query }"
        >
          <UButton color="primary" variant="soft">
            {{ shortcut.label }}
          </UButton>
        </ULink>
      </div>
      <p class="text-xs text-neutral-500 dark:text-neutral-400">
        Each shortcut opens the main catalog with these filters applied so teams can build patch queues or exports.
      </p>
    </section>

    <section class="space-y-6">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Dataset highlights</h2>
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <UCard>
          <template #header>Top vendors</template>
          <ul class="space-y-1 text-sm text-neutral-600 dark:text-neutral-300">
            <li v-for="item in topVendors" :key="item.key">
              <span class="font-semibold">{{ item.name }}</span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400"> — {{ item.count }} entries</span>
            </li>
          </ul>
        </UCard>
        <UCard>
          <template #header>Top products</template>
          <ul class="space-y-1 text-sm text-neutral-600 dark:text-neutral-300">
            <li v-for="item in topProducts" :key="item.key">
              <span class="font-semibold">{{ item.name }}</span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400"> — {{ item.count }} entries</span>
            </li>
          </ul>
        </UCard>
        <UCard>
          <template #header>Exploit techniques</template>
          <ul class="space-y-1 text-sm text-neutral-600 dark:text-neutral-300">
            <li v-for="item in topExploitLayers" :key="item.key">
              <span class="font-semibold">{{ item.name }}</span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400"> — {{ item.count }} entries</span>
            </li>
          </ul>
        </UCard>
        <UCard>
          <template #header>Vulnerability families</template>
          <ul class="space-y-1 text-sm text-neutral-600 dark:text-neutral-300">
            <li v-for="item in topVulnerabilities" :key="item.key">
              <span class="font-semibold">{{ item.name }}</span>
              <span class="text-xs text-neutral-500 dark:text-neutral-400"> — {{ item.count }} entries</span>
            </li>
          </ul>
        </UCard>
      </div>
    </section>

    <section v-if="topic.actions.length" class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Action panel</h2>
      <div class="grid gap-4 md:grid-cols-2">
        <UCard v-for="action in topic.actions" :key="action.title">
          <div class="space-y-2">
            <div class="flex items-center justify-between gap-3">
              <h3 class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                {{ action.title }}
              </h3>
              <UBadge v-if="action.owner" color="primary" variant="soft" class="text-xs">
                {{ action.owner }}
              </UBadge>
            </div>
            <p class="text-sm text-neutral-600 dark:text-neutral-300">
              {{ action.description }}
            </p>
            <div v-if="action.links?.length" class="flex flex-wrap gap-2 text-xs">
              <ULink
                v-for="link in action.links"
                :key="link.href"
                :to="link.href"
                target="_blank"
                rel="noopener noreferrer"
              >
                <UButton color="primary" variant="ghost" size="xs">
                  {{ link.label }}
                </UButton>
              </ULink>
            </div>
          </div>
        </UCard>
      </div>
    </section>

    <section v-if="topic.incidents.length" class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Incident library</h2>
      <div class="grid gap-4 md:grid-cols-2">
        <UCard v-for="incident in topic.incidents" :key="incident.title">
          <div class="space-y-2">
            <h3 class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
              {{ incident.title }}
            </h3>
            <p class="text-sm text-neutral-600 dark:text-neutral-300">
              {{ incident.summary }}
            </p>
            <ULink
              v-if="incident.url"
              :to="incident.url"
              target="_blank"
              rel="noopener noreferrer"
              class="text-xs text-primary-600 hover:underline dark:text-primary-300"
            >
              Read more
            </ULink>
          </div>
        </UCard>
      </div>
    </section>

    <section class="space-y-4">
      <h2 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">Curated vulnerability list</h2>
      <CatalogTable :entries="entries" :loading="pending" :total="totalEntries" />
    </section>
  </UContainer>
</template>
