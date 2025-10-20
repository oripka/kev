<script setup lang="ts">
import { computed } from "vue";
import { differenceInCalendarDays, parseISO } from "date-fns";
import type { TimelineItem } from "@nuxt/ui";
import { catalogSourceLabels } from "~/constants/catalogSources";
import type {
  CatalogSource,
  KevEntryDetail,
  KevEntrySummary,
  KevEntryTimelineEvent,
  KevTimelineEventType,
} from "~/types";
import { useDateDisplay } from "~/composables/useDateDisplay";

type SourceBadgeMap = Record<
  KevEntrySummary["sources"][number],
  { label: string; color: string }
>;

type CvssSeverity = Exclude<KevEntrySummary["cvssSeverity"], null>;

const props = defineProps<{
  open: boolean;
  entry: KevEntryDetail | null;
  loading: boolean;
  error: string | null;
  sourceBadgeMap: SourceBadgeMap;
  cvssSeverityColors: Record<CvssSeverity, string>;
  buildCvssLabel: (severity: KevEntrySummary["cvssSeverity"], score: number | null) => string;
  formatEpssScore: (score: number | null) => string | null;
  formatOptionalTimestamp: (value: string | null) => string;
  getWellKnownCveName: (cveId: string) => string | null;
}>();

type QuickFilterPayload = {
  filters?: Partial<{
    domain: string;
    exploit: string;
    vulnerability: string;
    vendor: string;
    product: string;
  }>;
  source?: CatalogSource;
  year?: number;
};

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "close"): void;
  (event: "quick-filter", payload: QuickFilterPayload): void;
}>();

const { formatDate } = useDateDisplay();

const isOpen = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const handleClose = () => {
  emit("close");
  emit("update:open", false);
};

const emitQuickFilter = (payload: QuickFilterPayload) => {
  emit("quick-filter", payload);
};

const handleSourceQuickFilter = (source: CatalogSource) => {
  emitQuickFilter({ source });
};

const handleDomainQuickFilter = (value: string) => {
  emitQuickFilter({ filters: { domain: value } });
};

const handleExploitQuickFilter = (value: string) => {
  emitQuickFilter({ filters: { exploit: value } });
};

const handleVulnerabilityQuickFilter = (value: string) => {
  emitQuickFilter({ filters: { vulnerability: value } });
};

const handleVendorQuickFilter = (vendorKey: string | undefined) => {
  if (!vendorKey) {
    return;
  }
  emitQuickFilter({ filters: { vendor: vendorKey } });
};

const handleProductQuickFilter = (productKey: string | undefined) => {
  if (!productKey) {
    return;
  }
  emitQuickFilter({ filters: { product: productKey } });
};

const handleYearQuickFilter = (value: string | null) => {
  if (!value) {
    return;
  }

  const parsed = parseISO(value);
  if (Number.isNaN(parsed.getTime())) {
    return;
  }

  emitQuickFilter({ year: parsed.getFullYear() });
};

type TimelineMeta = {
  icon: string;
  title: (event: KevEntryTimelineEvent, entry: KevEntryDetail) => string;
  description?: (event: KevEntryTimelineEvent, entry: KevEntryDetail) => string | null;
};

const getSourceLabel = (source: KevEntryTimelineEvent["source"]): string | null => {
  if (!source) {
    return null;
  }

  if (source === "nvd") {
    return "NVD";
  }

  return catalogSourceLabels[source as CatalogSource] ?? source.toUpperCase();
};

const timelineMeta: Record<KevTimelineEventType | "default", TimelineMeta> = {
  cve_published: {
    icon: "i-lucide-scroll-text",
    title: () => "CVE published",
    description: (_event, entry) =>
      entry.assigner?.trim()
        ? `Published by ${entry.assigner}.`
        : "Initial publication recorded in the NVD feed.",
  },
  kev_listed: {
    icon: "i-lucide-shield-check",
    title: () => `Flagged in ${catalogSourceLabels.kev}`,
    description: () =>
      "CISA confirmed active exploitation and added the CVE to the Known Exploited Vulnerabilities catalog.",
  },
  enisa_listed: {
    icon: "i-lucide-shield-half",
    title: () => `Listed by ${catalogSourceLabels.enisa}`,
    description: () =>
      "ENISA highlighted this CVE as actively exploited in the Threat Landscape for exploited vulnerabilities.",
  },
  metasploit_module: {
    icon: "i-lucide-swords",
    title: () => "Metasploit entry published",
    description: event => {
      const modulePath =
        typeof event.metadata?.modulePath === "string" && event.metadata.modulePath.trim().length
          ? event.metadata.modulePath
          : null;
      return modulePath ? `Module path: ${modulePath}` : "Exploit available in Metasploit.";
    },
  },
  historic_reference: {
    icon: "i-lucide-archive",
    title: () => "Historic exploitation noted",
    description: () => "Captured in the historic exploited vulnerability archive.",
  },
  exploitation_observed: {
    icon: "i-lucide-flame",
    title: () => "Exploitation observed",
    description: () => "Earliest available signal of in-the-wild exploitation.",
  },
  custom: {
    icon: "i-lucide-clock-8",
    title: () => "Timeline event",
    description: event => (typeof event.description === "string" ? event.description : null),
  },
  default: {
    icon: "i-lucide-clock-8",
    title: () => "Timeline event",
  },
};

const parseEventTimestamp = (value: string): Date | null => {
  const trimmed = value?.trim?.();
  if (!trimmed) {
    return null;
  }

  const parsed = new Date(trimmed);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const formatTimelineDate = (value: string | null | undefined): string | null => {
  if (!value) {
    return null;
  }

  return formatDate(value, { fallback: value, preserveInputOnError: true });
};

const sortedTimelineEvents = computed<KevEntryTimelineEvent[]>(() => {
  const entry = props.entry;
  if (!entry) {
    return [];
  }

  const events = [...(entry.timeline ?? [])];

  const addSyntheticEvent = (
    timestamp: string | null | undefined,
    build: (value: string) => KevEntryTimelineEvent,
  ) => {
    const value = timestamp?.trim?.();
    if (!value) {
      return;
    }

    const alreadyPresent = events.some(event => event.timestamp === value);
    if (alreadyPresent) {
      return;
    }

    events.push(build(value));
  };

  addSyntheticEvent(entry.exploitedSince, value => ({
    id: `exploited_since:${value}`,
    type: "custom",
    timestamp: value,
    title: "Exploited since",
    description: "Earliest exploitation date reported in the KEV catalog.",
    icon: "i-lucide-flame",
  }));

  addSyntheticEvent(entry.dateUpdated, value => ({
    id: `last_updated:${value}`,
    type: "custom",
    timestamp: value,
    title: "Last updated",
    description: "Most recent catalog update recorded for this entry.",
    icon: "i-lucide-rotate-cw",
  }));

  if (entry.metasploitModulePublishedAt) {
    const hasMetasploitEvent = events.some(event => event.type === "metasploit_module");
    if (!hasMetasploitEvent) {
      const metadata = (
        typeof entry.metasploitModulePath === "string" && entry.metasploitModulePath.trim().length
      )
        ? { modulePath: entry.metasploitModulePath }
        : undefined;

      events.push({
        id: `metasploit_module:${entry.metasploitModulePublishedAt}`,
        type: "metasploit_module",
        timestamp: entry.metasploitModulePublishedAt,
        source: "metasploit",
        ...(metadata ? { metadata } : {}),
      });
    }
  }

  if (!events.length) {
    return [];
  }

  events.sort((first, second) => {
    const firstDate = parseEventTimestamp(first.timestamp);
    const secondDate = parseEventTimestamp(second.timestamp);

    if (firstDate && secondDate) {
      return firstDate.getTime() - secondDate.getTime();
    }

    if (firstDate) {
      return -1;
    }

    if (secondDate) {
      return 1;
    }

    return first.timestamp.localeCompare(second.timestamp);
  });

  return events;
});

const getDateKey = (value: Date | null, fallback: string): string => {
  if (!value) {
    return fallback;
  }

  const year = value.getUTCFullYear();
  const month = String(value.getUTCMonth() + 1).padStart(2, "0");
  const day = String(value.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const buildGapLabel = (days: number): string => {
  if (!Number.isFinite(days) || days <= 0) {
    return "";
  }

  const parts: string[] = [];
  const years = Math.floor(days / 365);
  if (years > 0) {
    parts.push(`${years} year${years === 1 ? "" : "s"}`);
  }

  let remainingDays = days - years * 365;

  if (years === 0 && remainingDays >= 7 && remainingDays % 7 === 0) {
    const weeks = Math.floor(remainingDays / 7);
    if (weeks > 0) {
      parts.push(`${weeks} week${weeks === 1 ? "" : "s"}`);
      remainingDays = 0;
    }
  }

  if (remainingDays > 0) {
    parts.push(`${remainingDays} day${remainingDays === 1 ? "" : "s"}`);
  }

  return parts.join(" ");
};

const timelineItems = computed<TimelineItem[]>(() => {
  const entry = props.entry;
  if (!entry) {
    return [];
  }

  const events = sortedTimelineEvents.value;

  type TimelineGroup = {
    key: string;
    formattedDate: string;
    parsed: Date | null;
    events: KevEntryTimelineEvent[];
  };

  const groups: TimelineGroup[] = [];

  for (const event of events) {
    const parsed = parseEventTimestamp(event.timestamp);
    const formattedDate = formatTimelineDate(event.timestamp) ?? event.timestamp;
    const key = getDateKey(parsed, event.timestamp);

    const lastGroup = groups[groups.length - 1];
    if (lastGroup && lastGroup.key === key) {
      lastGroup.events.push(event);
      continue;
    }

    groups.push({
      key,
      formattedDate,
      parsed,
      events: [event],
    });
  }

  const items: TimelineItem[] = [];

  const buildEventDescription = (
    event: KevEntryTimelineEvent,
  ): { title: string; description: string | null; icon: string } => {
    const meta = timelineMeta[event.type] ?? timelineMeta.default;
    const title = event.title ?? meta.title(event, entry);
    const baseDescription = meta.description?.(event, entry) ?? null;
    const datasetLabel = getSourceLabel(event.source);

    let description = event.description ?? baseDescription ?? null;
    if (datasetLabel) {
      description = description
        ? `${description} · Source: ${datasetLabel}`
        : `Source: ${datasetLabel}`;
    }

    return {
      title,
      description,
      icon: event.icon ?? meta.icon,
    };
  };

  groups.forEach((group, groupIndex) => {
    if (groupIndex > 0) {
      const previous = groups[groupIndex - 1];
      if (group.parsed && previous.parsed) {
        const span = differenceInCalendarDays(group.parsed, previous.parsed);
        if (Number.isFinite(span) && span > 0) {
          const label = buildGapLabel(span);
          if (label) {
            items.push({
              value: items.length,
              date: "—",
              title: `${label} later`,
              description: "No tracked activity was recorded during this gap.",
              icon: "i-lucide-hourglass",
            });
          }
        }
      }
    }

    if (group.events.length === 1) {
      const [event] = group.events;
      const { title, description, icon } = buildEventDescription(event);
      items.push({
        value: items.length,
        date: group.formattedDate,
        title,
        ...(description ? { description } : {}),
        icon,
      });
      return;
    }

    const aggregated = group.events.map(event => {
      const { title, description } = buildEventDescription(event);
      const detail = description ? ` — ${description}` : "";
      return `• ${title}${detail}`;
    });

    items.push({
      value: items.length,
      date: group.formattedDate,
      title: `${group.events.length} events recorded`,
      description: aggregated.join("\n\n"),
      icon: "i-lucide-layers",
      ui: {
        description: "whitespace-pre-line",
      },
    });
  });

  return items;
});

const timelineEventCount = computed(() => sortedTimelineEvents.value.length);

const activeTimelineIndex = computed<number | undefined>(() => {
  const items = timelineItems.value;
  return items.length ? items.length - 1 : undefined;
});

const timelineStats = computed(() => {
  const events = sortedTimelineEvents.value;
  if (!events.length) {
    return null as const;
  }

  const first = parseEventTimestamp(events[0].timestamp);
  const last = parseEventTimestamp(events[events.length - 1].timestamp);

  let durationLabel: string | null = null;
  if (first && last) {
    const span = Math.abs(differenceInCalendarDays(last, first));
    if (Number.isFinite(span)) {
      durationLabel =
        span === 0
          ? "Progressed within a single day"
          : `${span} day${span === 1 ? "" : "s"} from first to latest milestone`;
    }
  }

  return {
    count: events.length,
    durationLabel,
  };
});

</script>

<template>
  <UModal
    v-model:open="isOpen"
    :ui="{
      content: 'w-full max-w-7xl rounded-xl shadow-lg',
      body: 'p-6 text-base text-muted',
    }"
  >
    <template #body>
      <div v-if="props.entry" class="relative space-y-4">
        <UCard>
          <template #header>
            <div class="space-y-1">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                {{ props.entry.vulnerabilityName }}
              </p>
              <div class="flex flex-wrap items-center gap-2 text-sm text-neutral-500 dark:text-neutral-400">
                <ULink
                  :href="`https://nvd.nist.gov/vuln/detail/${props.entry.cveId}`"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="font-medium text-primary-600 hover:underline dark:text-primary-400"
                >
                  {{ props.entry.cveId }}
                </ULink>
                <button
                  v-for="source in props.entry.sources"
                  :key="source"
                  type="button"
                  class="group rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 transition"
                  @click="handleSourceQuickFilter(source)"
                >
                  <UBadge
                    :color="props.sourceBadgeMap[source]?.color ?? 'neutral'"
                    variant="soft"
                    class="pointer-events-none text-xs font-semibold transition-colors group-hover:bg-primary-100/80 group-hover:text-primary-700 dark:group-hover:bg-primary-500/15 dark:group-hover:text-primary-200"
                  >
                    {{ props.sourceBadgeMap[source]?.label ?? source.toUpperCase() }}
                  </UBadge>
                </button>
              </div>
            </div>
          </template>

          <template #default>
            <div class="space-y-4">

              <div class="space-y-2">
                <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                  Description
                </p>
                <div class="flex flex-wrap items-start gap-2 text-sm leading-relaxed text-neutral-600 dark:text-neutral-300">
                  <UBadge
                    v-if="props.getWellKnownCveName(props.entry.cveId)"
                    color="primary"
                    variant="soft"
                    class="shrink-0 text-xs font-semibold"
                  >
                    {{ props.getWellKnownCveName(props.entry.cveId) }}
                  </UBadge>
                  <span class="max-w-4xl whitespace-normal break-words">
                    {{ props.entry.description || 'No description provided.' }}
                  </span>
                </div>
              </div>

              <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Vendor
                  </p>
                  <button
                    type="button"
                    class="rounded-md text-left text-base font-semibold text-neutral-900 transition hover:text-primary-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 dark:text-neutral-100 dark:hover:text-primary-300"
                    :aria-label="`Filter catalog by vendor ${props.entry.vendor}`"
                    @click="handleVendorQuickFilter(props.entry.vendorKey)"
                  >
                    {{ props.entry.vendor }}
                  </button>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Product
                  </p>
                  <button
                    type="button"
                    class="rounded-md text-left text-base font-semibold text-neutral-900 transition hover:text-primary-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 dark:text-neutral-100 dark:hover:text-primary-300"
                    :aria-label="`Filter catalog by product ${props.entry.product}`"
                    @click="handleProductQuickFilter(props.entry.productKey)"
                  >
                    {{ props.entry.product }}
                  </button>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Date added
                  </p>
                  <button
                    type="button"
                    class="rounded-md text-left text-base text-primary-600 transition hover:text-primary-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 dark:text-primary-300 dark:hover:text-primary-200"
                    :aria-label="`Filter catalog by year ${props.entry.dateAdded}`"
                    @click="handleYearQuickFilter(props.entry.dateAdded)"
                  >
                    {{ props.entry.dateAdded }}
                  </button>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Ransomware use
                  </p>
                  <p class="text-base text-neutral-900 dark:text-neutral-100">
                    {{ props.entry.ransomwareUse || 'Not specified' }}
                  </p>
                </div>
                <div class="space-y-1 col-span-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    CVSS
                  </p>
                  <div
                    v-if="props.entry.cvssScore !== null || props.entry.cvssSeverity"
                    class="flex items-center gap-2"
                  >
                    <UBadge
                      :color="
                        props.entry.cvssSeverity
                          ? props.cvssSeverityColors[props.entry.cvssSeverity] ?? 'neutral'
                          : 'neutral'
                      "
                      variant="soft"
                      class="font-semibold"
                    >
                      {{ props.buildCvssLabel(props.entry.cvssSeverity, props.entry.cvssScore) }}
                    </UBadge>
                    <span
                      v-if="props.entry.cvssVersion"
                      class="text-xs text-neutral-500 dark:text-neutral-400"
                    >
                      v{{ props.entry.cvssVersion }}
                    </span>
                  </div>
                  <p v-else class="text-base text-neutral-500 dark:text-neutral-400">
                    Not available
                  </p>
                  <p v-if="props.entry.cvssVector" class="text-xs font-mono text-neutral-600 dark:text-neutral-300 break-all">
                    {{ props.entry.cvssVector }}
                  </p>
                  <p v-else class="text-xs text-neutral-400 dark:text-neutral-500">
                    CVSS vector not available.
                  </p>
                </div>
                <div class="space-y-1">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    EPSS
                  </p>
                  <div v-if="props.formatEpssScore(props.entry.epssScore)" class="flex items-center gap-2">
                    <UBadge color="success" variant="soft" class="font-semibold">
                      {{ props.formatEpssScore(props.entry.epssScore) }}%
                    </UBadge>
                  </div>
                  <p v-else class="text-base text-neutral-500 dark:text-neutral-400">
                    Not available
                  </p>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Assigner
                  </p>
                  <p class="text-base text-neutral-900 dark:text-neutral-100">
                    {{ props.entry.assigner || 'Not available' }}
                  </p>
                </div>
              </div>



              <div
                class="relative overflow-hidden rounded-2xl border border-neutral-200 bg-white/80 p-4 shadow-sm dark:border-neutral-700 dark:bg-neutral-900"
              >
                <div
                  class="pointer-events-none absolute "
                />
                <div class="relative space-y-4">
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div class="space-y-1">
                      <p
                        class="text-xs font-semibold uppercase tracking-[0.3em] text-primary-600 dark:text-primary-300"
                      >
                        Exploit activity
                      </p>
                      <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                        Timeline of key milestones
                      </p>
                      <p class="text-sm text-neutral-600 dark:text-neutral-300">
                        Follow how this CVE moved from publication to active exploitation across monitored feeds.
                      </p>
                    </div>
                    <div class="flex flex-col items-end gap-1 text-right">
                      <UBadge
                        color="primary"
                        variant="soft"
                        class="text-xs font-semibold uppercase tracking-wide"
                      >
                        {{ timelineEventCount }}
                        {{ timelineEventCount === 1 ? "event" : "events" }}
                      </UBadge>
                      <span
                        v-if="timelineStats?.durationLabel"
                        class="text-xs text-neutral-500 dark:text-neutral-400"
                      >
                        {{ timelineStats.durationLabel }}
                      </span>
                    </div>
                  </div>

                  <div v-if="timelineItems.length">
                    <UTimeline
                      :items="timelineItems"
                      :default-value="activeTimelineIndex"
                      color="primary"
                      class="relative"
                    />
                  </div>
                  <div
                    v-else
                    class="rounded-xl border border-dashed border-neutral-200 bg-white/70 p-4 text-sm text-neutral-500 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-400"
                  >
                    We haven't captured enough milestone data for this vulnerability yet. As additional feeds confirm
                    exploitation, the timeline will light up automatically.
                  </div>
                </div>
              </div>

              <div class="space-y-2">
                <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                  Source
                </p>
                <div class="text-sm text-neutral-600 dark:text-neutral-300">
                  <template v-if="props.entry.sourceUrl">
                    <ULink
                      :href="props.entry.sourceUrl"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="font-medium text-primary-600 hover:underline dark:text-primary-400"
                    >
                      View advisory
                    </ULink>
                  </template>
                  <span v-else>Not available</span>
                </div>
              </div>

              <div class="grid gap-3 sm:grid-cols-3">
                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Domain categories
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <button
                      v-for="category in props.entry.domainCategories"
                      :key="category"
                      type="button"
                      class="group rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 transition"
                      @click="handleDomainQuickFilter(category)"
                    >
                      <UBadge
                        color="primary"
                        variant="soft"
                        class="pointer-events-none text-xs font-semibold transition-colors group-hover:bg-primary-100/80 group-hover:text-primary-700 dark:group-hover:bg-primary-500/15 dark:group-hover:text-primary-200"
                      >
                        {{ category }}
                      </UBadge>
                    </button>
                  </div>
                </div>
                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Exploit profiles
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <button
                      v-for="layer in props.entry.exploitLayers"
                      :key="layer"
                      type="button"
                      class="group rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 transition"
                      @click="handleExploitQuickFilter(layer)"
                    >
                      <UBadge
                        color="warning"
                        variant="soft"
                        class="pointer-events-none text-xs font-semibold transition-colors group-hover:bg-amber-100/80 group-hover:text-amber-700 dark:group-hover:bg-amber-500/15 dark:group-hover:text-amber-200"
                      >
                        {{ layer }}
                      </UBadge>
                    </button>
                  </div>
                </div>
                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Vulnerability categories
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <button
                      v-for="category in props.entry.vulnerabilityCategories"
                      :key="category"
                      type="button"
                      class="group rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500 transition"
                      @click="handleVulnerabilityQuickFilter(category)"
                    >
                      <UBadge
                        color="secondary"
                        variant="soft"
                        class="pointer-events-none text-xs font-semibold transition-colors group-hover:bg-rose-100/80 group-hover:text-rose-700 dark:group-hover:bg-rose-500/15 dark:group-hover:text-rose-200"
                      >
                        {{ category }}
                      </UBadge>
                    </button>
                  </div>
                </div>
              </div>

              <div v-if="props.entry.references.length" class="space-y-2">
                <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                  References
                </p>
                <ul class="list-disc space-y-1 pl-4 text-sm text-neutral-600 dark:text-neutral-300">
                  <li v-for="reference in props.entry.references" :key="reference">
                    <ULink
                      :href="reference"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="break-all text-primary-600 hover:underline dark:text-primary-400"
                    >
                      {{ reference }}
                    </ULink>
                  </li>
                </ul>
              </div>

              <div v-if="props.entry.aliases.length" class="space-y-2">
                <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                  Aliases
                </p>
                <div class="flex flex-wrap gap-2">
                  <UBadge
                    v-for="alias in props.entry.aliases"
                    :key="alias"
                    color="neutral"
                    variant="soft"
                  >
                    {{ alias }}
                  </UBadge>
                </div>
              </div>

              <div v-if="props.entry.notes.length" class="space-y-2">
                <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                  Notes
                </p>
                <ul class="list-disc space-y-1 pl-4 text-sm text-neutral-600 dark:text-neutral-300">
                  <li v-for="note in props.entry.notes" :key="note">
                    {{ note }}
                  </li>
                </ul>
              </div>
            </div>
          </template>

          <template #footer>
            <div class="flex justify-end gap-2">
              <UButton color="neutral" variant="soft" @click="handleClose">
                Close
              </UButton>
            </div>
          </template>
        </UCard>
        <div
          v-if="props.loading"
          class="pointer-events-none absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 rounded-xl bg-white/75 backdrop-blur dark:bg-neutral-950/80"
        >
          <UIcon name="i-lucide-loader-2" class="size-6 animate-spin text-primary-500" />
          <p class="text-sm font-medium text-neutral-600 dark:text-neutral-300">
            Loading vulnerability details…
          </p>
        </div>
        <p
          v-if="props.error"
          class="rounded-lg border border-error-200 bg-error-50 px-4 py-3 text-sm text-error-700 dark:border-error-500/50 dark:bg-error-500/10 dark:text-error-200"
        >
          {{ props.error }}
        </p>
      </div>
      <div
        v-else
        class="flex flex-col items-center gap-3 py-10 text-sm text-neutral-500 dark:text-neutral-400"
      >
        <UIcon name="i-lucide-search" class="size-6 text-neutral-400 dark:text-neutral-500" />
        <p>Select a vulnerability to view details.</p>
      </div>
    </template>
  </UModal>
</template>
