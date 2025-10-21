<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { parseISO } from "date-fns";
import type { TableColumn } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import { useDateDisplay } from "~/composables/useDateDisplay";
import {
  areQuickFilterSummaryConfigsEqual,
  cloneQuickFilterSummaryConfig,
  defaultQuickFilterSummaryConfig,
  normaliseQuickFilterSummaryConfig,
  quickFilterSummaryMetricInfo,
  quickFilterSummaryMetricOrder,
} from "~/utils/quickFilterSummaryConfig";
import type { ClassificationProgress, ImportTaskKey, ImportTaskStatus } from "~/types";
import type { QuickFilterSummaryConfig, QuickFilterSummaryMetricKey } from "~/types/dashboard";

interface ProductStat {
  vendorKey: string;
  vendorName: string;
  productKey: string;
  productName: string;
  selections: number;
}

interface VendorStat {
  vendorKey: string;
  vendorName: string;
  selections: number;
}

interface AdminSoftwareResponse {
  totals: {
    sessions: number;
    trackedSelections: number;
    uniqueProducts: number;
    uniqueVendors: number;
  };
  products: ProductStat[];
  vendors: VendorStat[];
}

interface ImportSourceStatus {
  key: string;
  label: string;
  catalogVersion: string | null;
  dateReleased: string | null;
  lastImportedAt: string | null;
  cachedAt: string | null;
  totalCount: number | null;
  programCount: number | null;
  latestCaptureAt: string | null;
}

interface AdminImportStatusResponse {
  sources: ImportSourceStatus[];
}

const { data, pending, error } = await useFetch<AdminSoftwareResponse>(
  "/api/admin/software",
  { default: () => ({
    totals: {
      sessions: 0,
      trackedSelections: 0,
      uniqueProducts: 0,
      uniqueVendors: 0,
    },
    products: [],
    vendors: [],
  }) }
);

const {
  data: importStatusData,
  pending: importStatusPending,
  error: importStatusError,
  refresh: refreshImportStatuses,
} = await useFetch<AdminImportStatusResponse>("/api/admin/import-status", {
  default: () => ({ sources: [] }),
  headers: {
    "cache-control": "no-store",
  },
});

const totals = computed(() => data.value?.totals ?? {
  sessions: 0,
  trackedSelections: 0,
  uniqueProducts: 0,
  uniqueVendors: 0,
});

const productStats = computed(() => data.value?.products ?? []);
const vendorStats = computed(() => data.value?.vendors ?? []);

const numberFormatter = new Intl.NumberFormat("en-US");

const importSources = computed(() => importStatusData.value?.sources ?? []);

const SOURCE_SUMMARY_LABELS: Record<ImportTaskKey, string> = {
  kev: "CISA KEV entries",
  historic: "historic entries",
  enisa: "ENISA entries",
  metasploit: "Metasploit entries",
  market: "market intelligence offers",
};

const { formatDate } = useDateDisplay();

const formatOptionalTimestamp = (value: string | null | undefined, fallback: string) => {
  if (!value) {
    return fallback;
  }

  return formatTimestamp(value);
};

interface FormattedImportSource {
  key: string;
  label: string;
  versionLabel: string | null;
  lastImportedLabel: string;
  cacheLabel: string;
  totalCountLabel: string | null;
  hasCache: boolean;
}

const formattedImportSources = computed<FormattedImportSource[]>(() =>
  importSources.value.map((source) => {
    const versionParts: string[] = [];
    if (source.catalogVersion) {
      versionParts.push(`Version ${source.catalogVersion}`);
    }
    if (source.dateReleased) {
      versionParts.push(`Released ${formatTimestamp(source.dateReleased)}`);
    }
    if (source.latestCaptureAt) {
      versionParts.push(`Latest capture ${formatTimestamp(source.latestCaptureAt)}`);
    }
    if (typeof source.programCount === "number") {
      versionParts.push(`${numberFormatter.format(source.programCount)} programs tracked`);
    }

    const versionLabel = versionParts.length ? versionParts.join(" • ") : null;
    const lastImportedLabel = formatOptionalTimestamp(source.lastImportedAt, "Never imported");
    const cacheTimestamp = source.cachedAt ?? source.lastImportedAt;
    const cacheLabel = formatOptionalTimestamp(cacheTimestamp, "No cached feed yet");
    const totalCountLabel =
      typeof source.totalCount === "number"
        ? `${numberFormatter.format(source.totalCount)} entries cached`
        : null;

    return {
      key: source.key,
      label: source.label,
      versionLabel,
      lastImportedLabel,
      cacheLabel,
      totalCountLabel,
      hasCache: Boolean(cacheTimestamp),
    } satisfies FormattedImportSource;
  }),
);

const productColumns: TableColumn<ProductStat>[] = [
  {
    accessorKey: "productName",
    header: "Product",
    enableSorting: true,
  },
  {
    accessorKey: "vendorName",
    header: "Vendor",
    enableSorting: true,
  },
  {
    accessorKey: "selections",
    header: "Selections",
    enableSorting: true,
    cell: ({ row }) => numberFormatter.format(row.getValue<number>("selections")),
    meta: {
      align: "end",
    },
  },
];

const {
  data: quickFilterSummaryConfigData,
  pending: quickFilterSummaryPending,
  error: quickFilterSummaryError,
} = await useFetch<QuickFilterSummaryConfig>(
  "/api/quick-filter-summary",
  {
    default: () => defaultQuickFilterSummaryConfig,
    headers: {
      "cache-control": "no-store",
    },
  },
);

const quickFilterSummaryForm = ref<QuickFilterSummaryConfig>(
  cloneQuickFilterSummaryConfig(defaultQuickFilterSummaryConfig),
);
const quickFilterSummarySaved = ref<QuickFilterSummaryConfig>(
  cloneQuickFilterSummaryConfig(defaultQuickFilterSummaryConfig),
);
const quickFilterSummarySaving = ref(false);
const quickFilterSummarySaveError = ref<string | null>(null);
const quickFilterSummarySaveSuccess = ref(false);

const quickFilterSummaryMetrics = computed(() =>
  quickFilterSummaryMetricOrder.map((key) => ({
    key,
    ...quickFilterSummaryMetricInfo[key],
  })),
);

const quickFilterSummaryDirty = computed(() =>
  !areQuickFilterSummaryConfigsEqual(
    quickFilterSummaryForm.value,
    quickFilterSummarySaved.value,
  ),
);

const quickFilterSummaryIsDefault = computed(() =>
  areQuickFilterSummaryConfigsEqual(
    quickFilterSummaryForm.value,
    defaultQuickFilterSummaryConfig,
  ),
);

watch(
  () => quickFilterSummaryConfigData.value,
  (config) => {
    const normalised = normaliseQuickFilterSummaryConfig(config);
    quickFilterSummaryForm.value = cloneQuickFilterSummaryConfig(normalised);
    quickFilterSummarySaved.value = cloneQuickFilterSummaryConfig(normalised);
    quickFilterSummarySaveError.value = null;
    quickFilterSummarySaveSuccess.value = false;
  },
  { immediate: true },
);

watch(quickFilterSummaryDirty, (dirty) => {
  if (dirty) {
    quickFilterSummarySaveSuccess.value = false;
  }
});

watch(
  () => quickFilterSummaryForm.value,
  () => {
    quickFilterSummarySaveError.value = null;
  },
  { deep: true },
);

const disableMetricToggle = (key: QuickFilterSummaryMetricKey) => {
  const metrics = quickFilterSummaryForm.value.metrics;
  return metrics.length === 1 && metrics.includes(key);
};

const toggleQuickFilterSummaryMetric = (
  key: QuickFilterSummaryMetricKey,
  selected: boolean,
) => {
  const metrics = new Set(quickFilterSummaryForm.value.metrics);
  if (selected) {
    metrics.add(key);
  } else {
    if (metrics.size === 1 && metrics.has(key)) {
      return;
    }
    metrics.delete(key);
  }

  quickFilterSummaryForm.value.metrics = quickFilterSummaryMetricOrder.filter((metric) =>
    metrics.has(metric),
  );
};

const setShowQuickFilterChips = (value: boolean) => {
  quickFilterSummaryForm.value.showActiveFilterChips = value;
};

const setShowQuickFilterResetButton = (value: boolean) => {
  quickFilterSummaryForm.value.showResetButton = value;
};

const restoreQuickFilterSummaryDefaults = () => {
  quickFilterSummaryForm.value = cloneQuickFilterSummaryConfig(
    defaultQuickFilterSummaryConfig,
  );
};

const saveQuickFilterSummaryConfig = async () => {
  if (!quickFilterSummaryDirty.value) {
    return;
  }

  quickFilterSummarySaving.value = true;
  quickFilterSummarySaveError.value = null;

  try {
    const response = await $fetch<QuickFilterSummaryConfig>(
      "/api/admin/quick-filter-summary",
      {
        method: "POST",
        body: quickFilterSummaryForm.value,
      },
    );

    const normalised = normaliseQuickFilterSummaryConfig(response);
    quickFilterSummaryForm.value = cloneQuickFilterSummaryConfig(normalised);
    quickFilterSummarySaved.value = cloneQuickFilterSummaryConfig(normalised);
    quickFilterSummarySaveSuccess.value = true;
    quickFilterSummaryConfigData.value = cloneQuickFilterSummaryConfig(normalised);
  } catch (exception) {
    quickFilterSummarySaveError.value =
      exception instanceof Error
        ? exception.message
        : "Unable to save configuration";
  } finally {
    quickFilterSummarySaving.value = false;
  }
};

const quickFilterSummaryStatusLabel = computed(() => {
  if (quickFilterSummarySaveError.value) {
    return quickFilterSummarySaveError.value;
  }
  if (quickFilterSummarySaveSuccess.value) {
    return "Configuration saved";
  }
  if (quickFilterSummaryDirty.value) {
    return "Unsaved changes";
  }
  return "No pending changes";
});

const quickFilterSummaryStatusTone = computed(() => {
  if (quickFilterSummarySaveError.value) {
    return "error" as const;
  }
  if (quickFilterSummarySaveSuccess.value) {
    return "success" as const;
  }
  if (quickFilterSummaryDirty.value) {
    return "warning" as const;
  }
  return "neutral" as const;
});

const quickFilterSummaryCanSave = computed(() =>
  quickFilterSummaryDirty.value && !quickFilterSummarySaving.value,
);

const quickFilterSummaryCanRestore = computed(() => !quickFilterSummaryIsDefault.value);

const vendorColumns: TableColumn<VendorStat>[] = [
  {
    accessorKey: "vendorName",
    header: "Vendor",
    enableSorting: true,
  },
  {
    accessorKey: "selections",
    header: "Tracked products",
    enableSorting: true,
    cell: ({ row }) => numberFormatter.format(row.getValue<number>("selections")),
    meta: {
      align: "end",
    },
  },
];

const {
  catalogBounds,
  updatedAt,
  importLatest,
  importing,
  importError,
  lastImportSummary,
  importProgress,
  entries,
  totalEntries,
  entryLimit,
  refresh: refreshKevData,
} = useKevData();

const formatTimestamp = (value: string) =>
  formatDate(value, { fallback: value, preserveInputOnError: true });

const catalogUpdatedAt = computed(() => {
  const summary = lastImportSummary.value;
  if (summary) {
    return formatTimestamp(summary.importedAt);
  }
  return updatedAt.value ? formatTimestamp(updatedAt.value) : "Not imported yet";
});

const handleImport = async (source: ImportTaskKey | "all" = "all") => {
  try {
    await importLatest({ mode: "force", source });
  } finally {
    await refreshImportStatuses();
  }
};

const handleCachedReimport = async (source: ImportTaskKey | "all" = "all") => {
  try {
    await importLatest({ mode: "cache", source });
  } finally {
    await refreshImportStatuses();
  }
};

const importProgressPhase = computed(() => importProgress.value.phase);
const importProgressPercent = computed(() => {
  const { total, completed, phase } = importProgress.value;
  if (phase === "complete") {
    return 100;
  }
  if (total > 0) {
    return Math.min(100, Math.round((completed / total) * 100));
  }
  if (phase === "preparing") {
    return 10;
  }
  if (phase === "enriching") {
    return 80;
  }
  if (
    phase === "fetchingEnisa" ||
    phase === "fetchingHistoric" ||
    phase === "fetchingMetasploit" ||
    phase === "fetchingMarket"
  ) {
    return 60;
  }
  if (
    phase === "saving" ||
    phase === "savingEnisa" ||
    phase === "savingHistoric" ||
    phase === "savingMetasploit" ||
    phase === "savingMarket"
  ) {
    return total === 0 ? 90 : Math.min(100, Math.round((completed / total) * 100));
  }
  return 0;
});

const showImportProgress = computed(() => {
  const phase = importProgressPhase.value;
  if (phase === "idle") {
    return importing.value;
  }
  if (phase === "complete") {
    return false;
  }
  return true;
});

const importProgressMessage = computed(() => {
  const { message, phase, error: progressError } = importProgress.value;
  if (phase === "idle" && importing.value) {
    return "Preparing catalog import…";
  }
  if (phase === "error" && progressError) {
    return progressError;
  }
  if (message) {
    return message;
  }
  return "Importing the latest vulnerability data…";
});

const hasProgressValue = computed(() => {
  const percent = importProgressPercent.value;
  return Number.isFinite(percent) && percent > 0 && percent <= 100;
});

const importTasks = computed(() => importProgress.value.tasks ?? []);

const taskStatusLabels: Record<ImportTaskStatus, string> = {
  pending: "Pending",
  running: "Running",
  complete: "Complete",
  skipped: "Skipped",
  error: "Failed",
};

const taskBadgeVariants: Record<ImportTaskStatus, string> = {
  pending: "neutral",
  running: "primary",
  complete: "success",
  skipped: "neutral",
  error: "error",
};

const taskDefaultMessages: Record<ImportTaskStatus, string> = {
  pending: "Waiting to start",
  running: "In progress…",
  complete: "Finished successfully",
  skipped: "Skipped for this run",
  error: "Encountered an error",
};

const formattedImportTasks = computed(() =>
  importTasks.value.map((task) => {
    const total = Math.max(0, task.total);
    const completed = Math.max(0, Math.min(task.completed, total || task.completed));
    const shouldShowPercent = total > 0 && (task.status === "running" || task.status === "complete");
    const percent = shouldShowPercent
      ? task.status === "complete"
        ? 100
        : Math.min(100, Math.round((completed / total) * 100))
      : null;
    const displayMessage = task.message?.length ? task.message : taskDefaultMessages[task.status];
    const progressLabel = total > 0 ? `${completed.toLocaleString()} of ${total.toLocaleString()}` : null;

    return {
      ...task,
      percent,
      progressLabel,
      statusLabel: taskStatusLabels[task.status],
      badgeVariant: taskBadgeVariants[task.status],
      displayMessage,
    };
  }),
);

const totalCachedEntries = computed(() => totalEntries.value);

const importSummaryMessage = computed(() => {
  const summary = lastImportSummary.value;
  if (!summary) {
    return null;
  }

  const counts: Record<ImportTaskKey, number> = {
    kev: summary.kevImported,
    historic: summary.historicImported,
    enisa: summary.enisaImported,
    metasploit: summary.metasploitImported,
    market: summary.marketImported,
  };

  const segments = summary.sources
    .map((source) => {
      const label = SOURCE_SUMMARY_LABELS[source];
      if (!label) {
        return null;
      }
      if (source === "metasploit") {
        const base = `${counts[source].toLocaleString()} ${label}`;
        return summary.metasploitModules > 0
          ? `${base} across ${summary.metasploitModules.toLocaleString()} modules`
          : base;
      }
      if (source === "market") {
        const base = `${counts[source].toLocaleString()} ${label}`;
        const extras: string[] = [];
        if (summary.marketProgramCount > 0) {
          extras.push(`${summary.marketProgramCount.toLocaleString()} programs`);
        }
        if (summary.marketProductCount > 0) {
          extras.push(`${summary.marketProductCount.toLocaleString()} matched products`);
        }
        if (!extras.length) {
          return base;
        }
        const scopeLabel =
          extras.length === 1
            ? extras[0]
            : `${extras.slice(0, -1).join(", ")} and ${extras[extras.length - 1]}`;
        return `${base} across ${scopeLabel}`;
      }
      return `${counts[source].toLocaleString()} ${label}`;
    })
    .filter((segment): segment is string => Boolean(segment));

  const importedAt = formatTimestamp(summary.importedAt);
  const messageParts: string[] = [];

  if (segments.length) {
    messageParts.push(`Imported ${segments.join(", ")} on ${importedAt}.`);
  } else {
    messageParts.push(`Import completed on ${importedAt}.`);
  }

  if (summary.sources.includes("kev")) {
    const kevDetails: string[] = [];
    if (summary.catalogVersion) {
      kevDetails.push(`catalog version ${summary.catalogVersion}`);
    }
    if (summary.dateReleased) {
      kevDetails.push(`release ${summary.dateReleased}`);
    }
    if (kevDetails.length) {
      messageParts.push(`Latest KEV ${kevDetails.join(", ")}.`);
    }
  }

  if (summary.sources.includes("enisa") && summary.enisaLastUpdated) {
    messageParts.push(`ENISA last updated ${formatTimestamp(summary.enisaLastUpdated)}.`);
  }

  if (summary.sources.includes("metasploit")) {
    if (summary.metasploitModules > 0) {
      const commitLabel = summary.metasploitCommit
        ? ` (commit ${summary.metasploitCommit.slice(0, 7)})`
        : "";
      messageParts.push(
        `Metasploit entries processed: ${summary.metasploitModules.toLocaleString()}${commitLabel}.`,
      );
    } else if (summary.metasploitCommit) {
      messageParts.push(`Metasploit repository at commit ${summary.metasploitCommit.slice(0, 7)}.`);
    }
  }

  if (summary.sources.includes("market")) {
    const details: string[] = [];
    if (summary.marketLastCaptureAt) {
      details.push(`latest offer captured ${formatTimestamp(summary.marketLastCaptureAt)}`);
    }
    if (summary.marketLastSnapshotAt) {
      details.push(`last snapshot ${formatTimestamp(summary.marketLastSnapshotAt)}`);
    }
    if (details.length) {
      messageParts.push(`Market intelligence ${details.join(" • ")}.`);
    }
  }

  return messageParts.join(" ");
});

const createDefaultClassificationProgress = (): ClassificationProgress => ({
  phase: "idle",
  completed: 0,
  total: 0,
  message: "",
  startedAt: null,
  updatedAt: null,
  error: null,
});

const {
  data: classificationProgress,
  refresh: refreshClassificationProgress,
} = await useFetch<ClassificationProgress>("/api/admin/reclassify/progress", {
  default: createDefaultClassificationProgress,
  headers: {
    "cache-control": "no-store",
  },
});

const classificationPhase = computed(() => classificationProgress.value.phase);

const classificationPercent = computed(() => {
  const { phase, total, completed } = classificationProgress.value;
  if (phase === "complete") {
    return 100;
  }
  if (total > 0) {
    return Math.min(100, Math.round((completed / total) * 100));
  }
  if (phase === "preparing") {
    return 10;
  }
  if (phase === "rebuilding") {
    return total === 0 ? 50 : Math.min(100, Math.round((completed / total) * 100));
  }
  return 0;
});

const classificationHasProgressValue = computed(() => {
  const percent = classificationPercent.value;
  return Number.isFinite(percent) && percent > 0 && percent <= 100;
});

const classificationMessage = computed(() => {
  const { message, phase, error: classificationError } = classificationProgress.value;
  if (phase === "error" && classificationError) {
    return classificationError;
  }
  if (message) {
    return message;
  }
  return "Reclassifying cached catalog…";
});

const showClassificationProgress = computed(
  () => classificationPhase.value === "preparing" || classificationPhase.value === "rebuilding",
);

const classificationCompleteMessage = computed(() =>
  classificationPhase.value === "complete" ? classificationProgress.value.message : null,
);

const classificationErrorMessage = computed(() => {
  if (classificationPhase.value !== "error") {
    return null;
  }

  return (
    classificationProgress.value.error ??
    classificationProgress.value.message ??
    "Unable to reclassify cached data"
  );
});

const isClassificationRunning = computed(
  () => classificationPhase.value === "preparing" || classificationPhase.value === "rebuilding",
);

const reclassifyingCatalog = ref(false);
const resettingDatabase = ref(false);

let classificationTimer: ReturnType<typeof setInterval> | null = null;
const shouldPollClassification = (phase: ClassificationProgress["phase"]) =>
  phase === "preparing" || phase === "rebuilding";

const startClassificationPolling = () => {
  if (typeof window === "undefined") {
    return;
  }
  if (!classificationTimer) {
    void refreshClassificationProgress();
    classificationTimer = setInterval(() => {
      void refreshClassificationProgress();
    }, 2_000);
  }
};

const stopClassificationPolling = () => {
  if (classificationTimer) {
    clearInterval(classificationTimer);
    classificationTimer = null;
  }
};

if (typeof window !== "undefined") {
  watch(
    () => classificationProgress.value.phase,
    (phase) => {
      if (shouldPollClassification(phase)) {
        startClassificationPolling();
      } else {
        stopClassificationPolling();
      }
    },
    { immediate: true },
  );

  onMounted(() => {
    void refreshClassificationProgress();
  });

  onBeforeUnmount(() => {
    stopClassificationPolling();
  });
}

const handleReclassify = async () => {
  reclassifyingCatalog.value = true;

  try {
    if (typeof window !== "undefined") {
      startClassificationPolling();
    }

    await $fetch("/api/admin/reclassify", { method: "POST" });
  } catch (exception) {
    console.error(exception);
  } finally {
    reclassifyingCatalog.value = false;
    await refreshClassificationProgress();
    await refreshKevData();
  }
};

const handleResetDatabase = async () => {
  resettingDatabase.value = true;

  try {
    stopClassificationPolling();
    await $fetch("/api/admin/reset", { method: "POST" });
  } catch (exception) {
    console.error(exception);
  } finally {
    await refreshKevData();
    await refreshClassificationProgress();
    await refreshImportStatuses();
    resettingDatabase.value = false;
  }
};

const catalogRangeLabel = computed(() => {
  const { earliest, latest } = catalogBounds.value;
  const formattedEarliest = earliest ? formatTimestamp(earliest) : "Unknown";
  const formattedLatest = latest ? formatTimestamp(latest) : "Unknown";

  if (!earliest && !latest) {
    return "Range unavailable";
  }

  return `${formattedEarliest} → ${formattedLatest}`;
});
</script>

<template>
  <UPage>
    <UPageBody>
      <div class="mx-auto grid w-full max-w-6xl gap-4 px-6">
        <UCard>
          <template #header>
            <div class="space-y-1">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Software tracking overview
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                An aggregate view of anonymous session filters saved for analysis.
              </p>
            </div>
          </template>

          <div class="grid gap-4 md:grid-cols-4">
            <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
              <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Sessions observed
              </p>
              <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                {{ numberFormatter.format(totals.sessions) }}
              </p>
            </div>
            <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
              <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Products tracked
              </p>
              <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                {{ numberFormatter.format(totals.trackedSelections) }}
              </p>
            </div>
            <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
              <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Unique products
              </p>
              <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                {{ numberFormatter.format(totals.uniqueProducts) }}
              </p>
            </div>
            <div class="rounded-lg border border-neutral-200 bg-neutral-50/60 p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
              <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Unique vendors
              </p>
              <p class="mt-2 text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
                {{ numberFormatter.format(totals.uniqueVendors) }}
              </p>
            </div>
          </div>

          <UAlert
            v-if="error"
            color="error"
            variant="soft"
            title="Unable to load usage data"
            :description="error.message"
            class="mt-4"
          />
          <p v-else-if="pending" class="mt-4 text-sm text-neutral-500 dark:text-neutral-400">
            Loading saved filter analytics…
          </p>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Data freshness
              </p>
              <UBadge color="neutral" variant="soft" class="text-xs font-semibold">
                {{ catalogUpdatedAt }}
              </UBadge>
            </div>
          </template>

          <div class="space-y-4">
            <div class="space-y-2">
              <p class="text-sm text-neutral-600 dark:text-neutral-300">
                Cached entries: <span class="font-semibold text-neutral-900 dark:text-neutral-100">{{ totalCachedEntries.toLocaleString() }}</span>
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Catalog coverage: {{ catalogRangeLabel }}
              </p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Dashboard lists the latest {{ entryLimit }} entries by default.
              </p>
              <p
                v-if="importSummaryMessage && !importError"
                class="text-xs text-neutral-500 dark:text-neutral-400"
              >
                {{ importSummaryMessage }}
              </p>
            </div>

            <div class="space-y-3">
              <UAlert
                v-if="importStatusError"
                color="error"
                variant="soft"
                icon="i-lucide-alert-triangle"
                title="Unable to load import history"
                :description="importStatusError.message"
              />
              <p
                v-else-if="importStatusPending"
                class="text-xs text-neutral-500 dark:text-neutral-400"
              >
                Loading cached import history…
              </p>
              <div v-else-if="formattedImportSources.length" class="space-y-3">
                <div
                  v-for="source in formattedImportSources"
                  :key="source.key"
                  class="flex flex-col gap-3 rounded-lg border border-neutral-200 bg-neutral-50/70 p-3 dark:border-neutral-800 dark:bg-neutral-900/40 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div class="space-y-1">
                    <p class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
                      {{ source.label }}
                    </p>
                    <p v-if="source.versionLabel" class="text-xs text-neutral-500 dark:text-neutral-400">
                      {{ source.versionLabel }}
                    </p>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">
                      Last import:
                      <span class="font-medium text-neutral-700 dark:text-neutral-200">
                        {{ source.lastImportedLabel }}
                      </span>
                    </p>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">
                      Cache:
                      <span class="font-medium text-neutral-700 dark:text-neutral-200">
                        {{ source.cacheLabel }}
                      </span>
                    </p>
                    <p v-if="source.totalCountLabel" class="text-xs text-neutral-500 dark:text-neutral-400">
                      {{ source.totalCountLabel }}
                    </p>
                  </div>
                  <div class="flex flex-wrap gap-2">
                    <UButton
                      size="sm"
                      color="primary"
                      variant="soft"
                      icon="i-lucide-cloud-download"
                      :disabled="importing"
                      :aria-label="`Fetch latest ${source.label}`"
                      @click="() => handleImport(source.key as ImportTaskKey)"
                    >
                      Fetch latest
                    </UButton>
                    <UButton
                      size="sm"
                      color="neutral"
                      variant="ghost"
                      icon="i-lucide-hard-drive-download"
                      :disabled="importing || !source.hasCache"
                      :aria-label="`Use cached ${source.label}`"
                      @click="() => handleCachedReimport(source.key as ImportTaskKey)"
                    >
                      Use cached feed
                    </UButton>
                  </div>
                </div>
              </div>
              <p v-else class="text-xs text-neutral-500 dark:text-neutral-400">
                No cached import history available yet.
              </p>
            </div>

            <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div class="flex flex-1 flex-wrap gap-2">
                <UButton
                  color="primary"
                  icon="i-lucide-cloud-download"
                  :loading="importing"
                  :disabled="importing"
                  @click="() => handleImport()"
                >
                  {{ importing ? "Importing…" : "Import latest data" }}
                </UButton>
                <UButton
                  color="neutral"
                  variant="soft"
                  icon="i-lucide-refresh-ccw"
                  :disabled="importing"
                  @click="() => handleCachedReimport()"
                >
                  Reimport cached data
                </UButton>
                <UButton
                  color="neutral"
                  variant="soft"
                  icon="i-lucide-layers"
                  :loading="reclassifyingCatalog"
                  :disabled="importing || resettingDatabase || reclassifyingCatalog || isClassificationRunning"
                  @click="handleReclassify"
                >
                  {{ reclassifyingCatalog ? "Reclassifying…" : "Reclassify cached data" }}
                </UButton>
                <UButton
                  color="error"
                  variant="soft"
                  icon="i-lucide-trash"
                  :loading="resettingDatabase"
                  :disabled="importing || resettingDatabase || reclassifyingCatalog || isClassificationRunning"
                  @click="handleResetDatabase"
                >
                  {{ resettingDatabase ? "Resetting cache…" : "Reset local cache" }}
                </UButton>
              </div>

              <div class="flex w-full flex-col gap-3 md:w-80">
                <UAlert
                  v-if="importError"
                  color="error"
                  variant="soft"
                  icon="i-lucide-alert-triangle"
                  title="Import failed"
                  :description="importError"
                />
                <div
                  v-else-if="showImportProgress"
                  class="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-300"
                >
                  <div class="flex items-center justify-between gap-3">
                    <span class="font-medium text-neutral-700 dark:text-neutral-200">
                      Import status
                    </span>
                    <span
                      v-if="hasProgressValue"
                      class="tabular-nums text-neutral-600 dark:text-neutral-300"
                    >
                      {{ importProgressPercent }}%
                    </span>
                  </div>
                  <UProgress
                    v-if="hasProgressValue"
                    :value="importProgressPercent"
                    size="xs"
                    :ui="{
                      rounded: 'rounded-md',
                      track: 'bg-neutral-200 dark:bg-neutral-800',
                      indicator: 'bg-primary-500 dark:bg-primary-400'
                    }"
                  />
                  <p class="mt-2 text-[0.78rem] text-neutral-500 dark:text-neutral-400">
                    {{ importProgressMessage }}
                  </p>
                  <div v-if="formattedImportTasks.length" class="mt-3 space-y-2">
                    <div
                      v-for="task in formattedImportTasks"
                      :key="task.key"
                      class="rounded-md border border-neutral-200/80 bg-white/70 p-2 text-[0.72rem] dark:border-neutral-800 dark:bg-neutral-900/40"
                    >
                      <div class="flex items-center justify-between gap-3">
                        <div class="space-y-1">
                          <p class="font-medium text-neutral-700 dark:text-neutral-100">
                            {{ task.label }}
                          </p>
                          <p class="text-[0.68rem] text-neutral-500 dark:text-neutral-400">
                            {{ task.displayMessage }}
                          </p>
                        </div>
                        <UBadge :color="task.badgeVariant" variant="soft" class="shrink-0 text-[0.65rem]">
                          {{ task.statusLabel }}
                        </UBadge>
                      </div>
                      <div v-if="task.percent !== null || task.progressLabel" class="mt-2 space-y-1">
                        <UProgress
                          v-if="task.percent !== null"
                          :value="task.percent"
                          size="xs"
                          :ui="{
                            rounded: 'rounded-md',
                            track: 'bg-neutral-200 dark:bg-neutral-800',
                            indicator: 'bg-primary-500 dark:bg-primary-400'
                          }"
                        />
                        <p
                          v-if="task.progressLabel"
                          class="text-[0.65rem] uppercase tracking-wide text-neutral-400 dark:text-neutral-500"
                        >
                          {{ task.progressLabel }}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <div
                  v-if="showClassificationProgress"
                  class="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-300"
                >
                  <div class="flex items-center justify-between gap-3">
                    <span class="font-medium text-neutral-700 dark:text-neutral-200">
                      Classification status
                    </span>
                    <span
                      v-if="classificationHasProgressValue"
                      class="tabular-nums text-neutral-600 dark:text-neutral-300"
                    >
                      {{ classificationPercent }}%
                    </span>
                  </div>
                  <UProgress
                    v-if="classificationHasProgressValue"
                    :value="classificationPercent"
                    size="xs"
                    :ui="{
                      rounded: 'rounded-md',
                      track: 'bg-neutral-200 dark:bg-neutral-800',
                      indicator: 'bg-primary-500 dark:bg-primary-400'
                    }"
                  />
                  <p class="mt-2 text-[0.78rem] text-neutral-500 dark:text-neutral-400">
                    {{ classificationMessage }}
                  </p>
                </div>
                <UAlert
                  v-else-if="classificationErrorMessage"
                  color="error"
                  variant="soft"
                  icon="i-lucide-alert-octagon"
                  title="Reclassification failed"
                  :description="classificationErrorMessage"
                />
                <UAlert
                  v-else-if="classificationCompleteMessage"
                  color="success"
                  variant="soft"
                  icon="i-lucide-check-circle"
                  title="Reclassification complete"
                  :description="classificationCompleteMessage"
                />
              </div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="space-y-1">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Quick filter summary
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                Choose which metrics appear above the catalog and how the clear controls behave.
              </p>
            </div>
          </template>

          <UAlert
            v-if="quickFilterSummaryError"
            color="error"
            variant="soft"
            icon="i-lucide-alert-triangle"
            title="Unable to load quick filter settings"
            :description="quickFilterSummaryError.message"
          />
          <p
            v-else-if="quickFilterSummaryPending"
            class="text-sm text-neutral-500 dark:text-neutral-400"
          >
            Loading quick filter preferences…
          </p>
          <div v-else class="space-y-6">
            <div class="space-y-3">
              <div>
                <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
                  Visible metrics
                </p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                  Enable the summary chips shown in the dashboard header.
                </p>
              </div>
              <div class="grid gap-3 sm:grid-cols-2">
                <label
                  v-for="metric in quickFilterSummaryMetrics"
                  :key="metric.key"
                  class="flex items-start gap-3 rounded-lg border border-neutral-200 bg-neutral-50/60 p-3 dark:border-neutral-800 dark:bg-neutral-900/40"
                >
                  <UCheckbox
                    :model-value="quickFilterSummaryForm.metrics.includes(metric.key)"
                    :disabled="disableMetricToggle(metric.key)"
                    @update:model-value="(value) => toggleQuickFilterSummaryMetric(metric.key, value)"
                  />
                  <div class="space-y-1">
                    <div class="flex items-center gap-2">
                      <UIcon :name="metric.icon" class="size-4 text-primary-500 dark:text-primary-400" />
                      <p class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">
                        {{ metric.label }}
                      </p>
                    </div>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">
                      {{ metric.description }}
                    </p>
                  </div>
                </label>
              </div>
            </div>

            <div class="grid gap-3 md:grid-cols-2">
              <div class="flex items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-neutral-50/60 p-3 dark:border-neutral-800 dark:bg-neutral-900/40">
                <div>
                  <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
                    Show active filter chips
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Display applied filters inside the summary pill.
                  </p>
                </div>
                <USwitch
                  :model-value="quickFilterSummaryForm.showActiveFilterChips"
                  @update:model-value="setShowQuickFilterChips"
                />
              </div>

              <div class="flex items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-neutral-50/60 p-3 dark:border-neutral-800 dark:bg-neutral-900/40">
                <div>
                  <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">
                    Show reset button
                  </p>
                  <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Allow analysts to clear all filters from the summary.
                  </p>
                </div>
                <USwitch
                  :model-value="quickFilterSummaryForm.showResetButton"
                  @update:model-value="setShowQuickFilterResetButton"
                />
              </div>
            </div>

            <div class="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-neutral-50/60 p-3 dark:border-neutral-800 dark:bg-neutral-900/40">
              <UBadge :color="quickFilterSummaryStatusTone" variant="soft" class="text-xs font-semibold">
                {{ quickFilterSummaryStatusLabel }}
              </UBadge>
              <div class="flex items-center gap-2">
                <UButton
                  color="neutral"
                  variant="ghost"
                  :disabled="!quickFilterSummaryCanRestore || quickFilterSummarySaving"
                  @click="restoreQuickFilterSummaryDefaults"
                >
                  Restore defaults
                </UButton>
                <UButton
                  color="primary"
                  :loading="quickFilterSummarySaving"
                  :disabled="!quickFilterSummaryCanSave"
                  @click="saveQuickFilterSummaryConfig"
                >
                  Save changes
                </UButton>
              </div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex items-center justify-between">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Most tracked products
              </p>
              <UBadge color="secondary" variant="soft" class="text-sm font-semibold">
                {{ numberFormatter.format(productStats.length) }}
              </UBadge>
            </div>
          </template>

          <div v-if="productStats.length" class="space-y-4">
            <UTable :data="productStats" :columns="productColumns" />
          </div>
          <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
            No product selections recorded yet.
          </p>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex items-center justify-between">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Top vendors in saved filters
              </p>
              <UBadge color="primary" variant="soft" class="text-sm font-semibold">
                {{ numberFormatter.format(vendorStats.length) }}
              </UBadge>
            </div>
          </template>

          <div v-if="vendorStats.length" class="space-y-4">
            <UTable :data="vendorStats" :columns="vendorColumns" />
          </div>
          <p v-else class="text-sm text-neutral-500 dark:text-neutral-400">
            No vendor data recorded yet.
          </p>
        </UCard>
      </div>
    </UPageBody>
  </UPage>
</template>
