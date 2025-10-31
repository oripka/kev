<script setup lang="ts">
definePageMeta({ middleware: ["admin"] });

import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useKevData } from "~/composables/useKevData";
import { useDateDisplay } from "~/composables/useDateDisplay";
import type {
  ClassificationProgress,
  ImportProgressEvent,
  ImportProgressEventStatus,
  ImportTaskKey,
  ImportTaskStatus,
} from "~/types";

type ImportSourceStatus = {
  key: string;
  label: string;
  importKey: ImportTaskKey | null;
  catalogVersion: string | null;
  dateReleased: string | null;
  lastImportedAt: string | null;
  cachedAt: string | null;
  totalCount: number | null;
  programCount: number | null;
  latestCaptureAt: string | null;
};

type KevImportSummary = {
  lastImportedAt: string | null;
  newCount: number;
  updatedCount: number;
  skippedCount: number;
  removedCount: number;
  strategy: "full" | "incremental";
};

type AdminImportStatusResponse = {
  sources: ImportSourceStatus[];
  kevSummary: KevImportSummary | null;
};

const SOURCE_SUMMARY_LABELS: Record<ImportTaskKey, string> = {
  kev: "CISA KEV entries",
  historic: "historic entries",
  custom: "curated entries",
  enisa: "ENISA entries",
  metasploit: "Metasploit entries",
  poc: "GitHub PoC entries",
  market: "market intelligence offers",
};

const INCREMENTAL_IMPORT_SOURCES = new Set<ImportTaskKey>([
  "kev",
  "historic",
  "custom",
  "enisa",
  "metasploit",
  "poc",
]);

const isDevEnvironment = import.meta.dev;

const numberFormatter = new Intl.NumberFormat("en-US");

const {
  catalogBounds,
  updatedAt,
  importLatest,
  importing,
  importError,
  lastImportSummary,
  importProgress,
  totalEntries,
  entryLimit,
  refresh: refreshKevData,
} = useKevData();

const {
  data: importStatusData,
  pending: importStatusPending,
  error: importStatusError,
  refresh: refreshImportStatuses,
} = await useFetch<AdminImportStatusResponse>("/api/admin/import-status", {
  default: () => ({ sources: [], kevSummary: null }),
  headers: {
    "cache-control": "no-store",
  },
});

const extractStatusCode = (error: unknown): number | null => {
  if (!error || typeof error !== "object" || error === null) {
    return null;
  }
  const withStatus = error as {
    statusCode?: number;
    status?: number;
    response?: { status?: number } | null;
  };
  if (typeof withStatus.statusCode === "number") {
    return withStatus.statusCode;
  }
  if (typeof withStatus.status === "number") {
    return withStatus.status;
  }
  const response = withStatus.response;
  if (response && typeof response === "object" && response !== null) {
    const responseWithStatus = response as { status?: number };
    if (typeof responseWithStatus.status === "number") {
      return responseWithStatus.status;
    }
  }
  return null;
};

const importStatusCode = computed(() => extractStatusCode(importStatusError.value));
const importStatusForbidden = computed(() => {
  const status = importStatusCode.value;
  return status === 401 || status === 403;
});
const importStatusFetchFailed = computed(
  () => Boolean(importStatusError.value) && !importStatusForbidden.value,
);
const adminActionsDisabled = computed(
  () => !isDevEnvironment || importStatusForbidden.value,
);
const adminActionsVisible = computed(() => isDevEnvironment && !importStatusForbidden.value);

const importSources = computed(() => importStatusData.value?.sources ?? []);
const importEvents = computed(() => importProgress.value.events ?? []);
const kevSummaryFromStatus = computed(() => importStatusData.value?.kevSummary ?? null);

type FormattedImportSource = {
  key: string;
  label: string;
  importKey: ImportTaskKey | null;
  versionLabel: string | null;
  lastActionPrefix: string;
  lastActionValue: string;
  cacheLabel: string;
  totalCountLabel: string | null;
  hasCache: boolean;
  supportsImport: boolean;
  supportsIncremental: boolean;
};

type FormattedImportEvent = {
  id: string;
  timestampLabel: string;
  message: string;
  status: ImportProgressEventStatus;
  badgeVariant: string;
  taskLabel: string | null;
};

type KevSummaryBadge = {
  key: string;
  label: string;
  value: number;
  color: string;
};

const { formatDate } = useDateDisplay();

const formatTimestamp = (value: string) =>
  formatDate(value, { fallback: value, preserveInputOnError: true });

const formatOptionalTimestamp = (
  value: string | null | undefined,
  fallback: string,
) => {
  if (!value) {
    return fallback;
  }

  return formatTimestamp(value);
};

const formattedImportSources = computed<FormattedImportSource[]>(() =>
  importSources.value.map((source) => {
    const versionParts: string[] = [];
    if (source.catalogVersion) {
      const versionLabel = source.key === "cvelist"
        ? `Commit ${source.catalogVersion}`
        : `Version ${source.catalogVersion}`;
      versionParts.push(versionLabel);
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
    const lastActionPrefix = source.key === "cvelist" ? "Last refresh" : "Last import";
    const lastActionFallback = source.key === "cvelist" ? "Never refreshed" : "Never imported";
    const lastActionValue = formatOptionalTimestamp(source.lastImportedAt, lastActionFallback);
    const cacheTimestamp = source.cachedAt ?? source.lastImportedAt;
    const cacheFallback = source.key === "cvelist" ? "No repository sync yet" : "No cached feed yet";
    const cacheLabel = formatOptionalTimestamp(
      cacheTimestamp,
      cacheFallback,
    );
    const totalCountLabel =
      typeof source.totalCount === "number"
        ? `${numberFormatter.format(source.totalCount)} entries cached`
        : null;

    return {
      key: source.key,
      label: source.label,
      importKey: source.importKey,
      versionLabel,
      lastActionPrefix,
      lastActionValue,
      cacheLabel,
      totalCountLabel,
      hasCache: Boolean(cacheTimestamp),
      supportsImport: Boolean(source.importKey),
      supportsIncremental: Boolean(source.importKey && INCREMENTAL_IMPORT_SOURCES.has(source.importKey)),
    } satisfies FormattedImportSource;
  }),
);

const eventBadgeVariants: Record<ImportProgressEventStatus, string> = {
  pending: "neutral",
  running: "primary",
  complete: "success",
  skipped: "neutral",
  error: "error",
  info: "neutral",
};

const eventStatusLabels: Record<ImportProgressEventStatus, string> = {
  pending: "Pending",
  running: "Running",
  complete: "Complete",
  skipped: "Skipped",
  error: "Failed",
  info: "Info",
};

const formattedImportEvents = computed<FormattedImportEvent[]>(() =>
  importEvents.value
    .slice()
    .reverse()
    .map((event: ImportProgressEvent) => {
      const timestampLabel = formatOptionalTimestamp(event.timestamp, "Timestamp unavailable");
      const badgeVariant = eventBadgeVariants[event.status] ?? "neutral";
      const taskLabel = event.taskLabel ?? null;

      return {
        id: event.id,
        timestampLabel,
        message: event.message,
        status: event.status,
        badgeVariant,
        taskLabel,
      } satisfies FormattedImportEvent;
    }),
);

const resolvedKevImportSummary = computed<KevImportSummary | null>(() => {
  const summary = lastImportSummary.value;
  if (summary && summary.sources.includes("kev")) {
    return {
      lastImportedAt: summary.importedAt,
      newCount: summary.kevNewCount,
      updatedCount: summary.kevUpdatedCount,
      skippedCount: summary.kevSkippedCount,
      removedCount: summary.kevRemovedCount,
      strategy: summary.kevImportStrategy,
    } satisfies KevImportSummary;
  }
  return kevSummaryFromStatus.value;
});

const kevImportSummaryDescription = computed(() => {
  const summary = resolvedKevImportSummary.value;
  if (!summary) {
    return null;
  }
  const strategyLabel = summary.strategy === "incremental" ? "incremental update" : "full import";
  const timestamp = summary.lastImportedAt ? formatTimestamp(summary.lastImportedAt) : null;
  return timestamp ? `Last KEV ${strategyLabel} on ${timestamp}` : `Last KEV ${strategyLabel}`;
});

const kevSummaryBadges = computed<KevSummaryBadge[]>(() => {
  const summary = resolvedKevImportSummary.value;
  if (!summary) {
    return [];
  }
  return [
    { key: "new", label: "New", value: summary.newCount, color: "success" },
    { key: "updated", label: "Updated", value: summary.updatedCount, color: "primary" },
    { key: "unchanged", label: "Unchanged", value: summary.skippedCount, color: "neutral" },
    { key: "removed", label: "Removed", value: summary.removedCount, color: "error" },
  ];
});

const hasKevImportSummary = computed(() => Boolean(resolvedKevImportSummary.value));

const totalCachedEntries = computed(() => totalEntries.value);

const importSummaryMessage = computed(() => {
  const summary = lastImportSummary.value;
  if (!summary) {
    return null;
  }

  const counts: Record<ImportTaskKey, number> = {
    kev: summary.kevImported,
    historic: summary.historicImported,
    custom: summary.customImported,
    enisa: summary.enisaImported,
    metasploit: summary.metasploitImported,
    poc: summary.pocImported,
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
    if (summary.kevImportStrategy === "incremental") {
      const kevChanges: string[] = [];
      if (summary.kevNewCount > 0) {
        kevChanges.push(`${summary.kevNewCount.toLocaleString()} new`);
      }
      if (summary.kevUpdatedCount > 0) {
        kevChanges.push(`${summary.kevUpdatedCount.toLocaleString()} updated`);
      }
      if (summary.kevSkippedCount > 0) {
        kevChanges.push(`${summary.kevSkippedCount.toLocaleString()} unchanged`);
      }
      if (summary.kevRemovedCount > 0) {
        kevChanges.push(`${summary.kevRemovedCount.toLocaleString()} removed`);
      }
      if (kevChanges.length) {
        messageParts.push(`Incremental KEV update touched ${kevChanges.join(", ")}.`);
      } else {
        messageParts.push("Incremental KEV update detected no changes.");
      }
    }

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

  if (summary.sources.includes("historic") && summary.historicImportStrategy === "incremental") {
    const historicChanges: string[] = [];
    if (summary.historicNewCount > 0) {
      historicChanges.push(`${summary.historicNewCount.toLocaleString()} new`);
    }
    if (summary.historicUpdatedCount > 0) {
      historicChanges.push(`${summary.historicUpdatedCount.toLocaleString()} updated`);
    }
    if (summary.historicSkippedCount > 0) {
      historicChanges.push(`${summary.historicSkippedCount.toLocaleString()} unchanged`);
    }
    if (summary.historicRemovedCount > 0) {
      historicChanges.push(`${summary.historicRemovedCount.toLocaleString()} removed`);
    }
    if (historicChanges.length) {
      messageParts.push(`Incremental historic update touched ${historicChanges.join(", ")}.`);
    } else {
      messageParts.push("Incremental historic update detected no changes.");
    }
  }

  if (summary.sources.includes("custom") && summary.customImportStrategy === "incremental") {
    const customChanges: string[] = [];
    if (summary.customNewCount > 0) {
      customChanges.push(`${summary.customNewCount.toLocaleString()} new`);
    }
    if (summary.customUpdatedCount > 0) {
      customChanges.push(`${summary.customUpdatedCount.toLocaleString()} updated`);
    }
    if (summary.customSkippedCount > 0) {
      customChanges.push(`${summary.customSkippedCount.toLocaleString()} unchanged`);
    }
    if (summary.customRemovedCount > 0) {
      customChanges.push(`${summary.customRemovedCount.toLocaleString()} removed`);
    }
    if (customChanges.length) {
      messageParts.push(`Incremental curated update touched ${customChanges.join(", ")}.`);
    } else {
      messageParts.push("Incremental curated update detected no changes.");
    }
  }

  if (summary.sources.includes("enisa") && summary.enisaImportStrategy === "incremental") {
    const enisaChanges: string[] = [];
    if (summary.enisaNewCount > 0) {
      enisaChanges.push(`${summary.enisaNewCount.toLocaleString()} new`);
    }
    if (summary.enisaUpdatedCount > 0) {
      enisaChanges.push(`${summary.enisaUpdatedCount.toLocaleString()} updated`);
    }
    if (summary.enisaSkippedCount > 0) {
      enisaChanges.push(`${summary.enisaSkippedCount.toLocaleString()} unchanged`);
    }
    if (summary.enisaRemovedCount > 0) {
      enisaChanges.push(`${summary.enisaRemovedCount.toLocaleString()} removed`);
    }
    if (enisaChanges.length) {
      messageParts.push(`Incremental ENISA update touched ${enisaChanges.join(", ")}.`);
    } else {
      messageParts.push("Incremental ENISA update detected no changes.");
    }
  }

  if (summary.sources.includes("metasploit") && summary.metasploitImportStrategy === "incremental") {
    const metasploitChanges: string[] = [];
    if (summary.metasploitNewCount > 0) {
      metasploitChanges.push(`${summary.metasploitNewCount.toLocaleString()} new`);
    }
    if (summary.metasploitUpdatedCount > 0) {
      metasploitChanges.push(`${summary.metasploitUpdatedCount.toLocaleString()} updated`);
    }
    if (summary.metasploitSkippedCount > 0) {
      metasploitChanges.push(`${summary.metasploitSkippedCount.toLocaleString()} unchanged`);
    }
    if (summary.metasploitRemovedCount > 0) {
      metasploitChanges.push(`${summary.metasploitRemovedCount.toLocaleString()} removed`);
    }
    if (metasploitChanges.length) {
      messageParts.push(`Incremental Metasploit update touched ${metasploitChanges.join(", ")}.`);
    } else {
      messageParts.push("Incremental Metasploit update detected no changes.");
    }
  }

  if (summary.sources.includes("poc") && summary.pocImportStrategy === "incremental") {
    const pocChanges: string[] = [];
    if (summary.pocNewCount > 0) {
      pocChanges.push(`${summary.pocNewCount.toLocaleString()} new`);
    }
    if (summary.pocUpdatedCount > 0) {
      pocChanges.push(`${summary.pocUpdatedCount.toLocaleString()} updated`);
    }
    if (summary.pocSkippedCount > 0) {
      pocChanges.push(`${summary.pocSkippedCount.toLocaleString()} unchanged`);
    }
    if (summary.pocRemovedCount > 0) {
      pocChanges.push(`${summary.pocRemovedCount.toLocaleString()} removed`);
    }
    if (pocChanges.length) {
      messageParts.push(`Incremental GitHub PoC update touched ${pocChanges.join(", ")}.`);
    } else {
      messageParts.push("Incremental GitHub PoC update detected no changes.");
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

const catalogUpdatedAt = computed(() => {
  const summary = lastImportSummary.value;
  if (summary) {
    return formatTimestamp(summary.importedAt);
  }
  return updatedAt.value ? formatTimestamp(updatedAt.value) : "Not imported yet";
});

const catalogRangeLabel = computed(() => {
  const { earliest, latest } = catalogBounds.value;
  const formattedEarliest = earliest ? formatTimestamp(earliest) : "Unknown";
  const formattedLatest = latest ? formatTimestamp(latest) : "Unknown";

  if (!earliest && !latest) {
    return "Range unavailable";
  }

  return `${formattedEarliest} → ${formattedLatest}`;
});

const handleImport = async (source: ImportTaskKey | "all" = "all") => {
  if (adminActionsDisabled.value) {
    return;
  }

  try {
    await importLatest({ mode: "force", source });
  } finally {
    await refreshImportStatuses();
  }
};

const handleIncrementalImport = async (source: ImportTaskKey | "all" = "all") => {
  if (adminActionsDisabled.value) {
    return;
  }

  try {
    await importLatest({ mode: "force", source, strategy: "incremental" });
  } finally {
    await refreshImportStatuses();
  }
};

const handleCachedReimport = async (source: ImportTaskKey | "all" = "all") => {
  if (adminActionsDisabled.value) {
    return;
  }

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
    phase === "fetchingPoc" ||
    phase === "fetchingMarket"
  ) {
    return 60;
  }
  if (
    phase === "saving" ||
    phase === "savingEnisa" ||
    phase === "savingHistoric" ||
    phase === "savingMetasploit" ||
    phase === "savingPoc" ||
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
  if (adminActionsDisabled.value) {
    return;
  }

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
  if (adminActionsDisabled.value) {
    return;
  }

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
</script>

<template>
  <UPage>
    <UPageBody>
      <div class="mx-auto flex w-full max-w-5xl flex-col gap-4 px-6">
        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                  Catalog maintenance
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Review cached feed history and refresh local data.
                </p>
              </div>
              <UBadge color="neutral" variant="soft" class="text-xs font-semibold">
                {{ catalogUpdatedAt }}
              </UBadge>
            </div>
          </template>

          <div class="space-y-4">
            <div class="space-y-2">
              <p class="text-sm text-neutral-600 dark:text-neutral-300">
                Cached entries:
                <span class="font-semibold text-neutral-900 dark:text-neutral-100">
                  {{ totalCachedEntries.toLocaleString() }}
                </span>
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
              <div
                v-if="hasKevImportSummary && kevSummaryBadges.length"
                class="space-y-1 text-xs text-neutral-500 dark:text-neutral-400"
              >
                <p>
                  {{ kevImportSummaryDescription }}.
                </p>
                <div class="flex flex-wrap gap-2">
                  <UBadge
                    v-for="badge in kevSummaryBadges"
                    :key="badge.key"
                    :color="badge.color"
                    variant="soft"
                    class="text-[11px] font-semibold"
                  >
                    {{ badge.label }} {{ numberFormatter.format(badge.value) }}
                  </UBadge>
                </div>
              </div>
              <UAlert
                v-if="!isDevEnvironment"
                color="neutral"
                variant="soft"
                icon="i-lucide-lock"
                title="Development only"
                description="Catalog maintenance actions are disabled outside development mode."
              />
            </div>

            <div class="space-y-3">
              <UAlert
                v-if="importStatusForbidden"
                color="neutral"
                variant="soft"
                icon="i-lucide-lock"
                title="Admin API key required"
                description="Provide the admin API key to view import history in production."
              />
              <UAlert
                v-else-if="importStatusFetchFailed"
                color="error"
                variant="soft"
                icon="i-lucide-alert-triangle"
                title="Unable to load import history"
                :description="importStatusError?.message ?? 'Unexpected error while fetching import history.'"
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
                      {{ source.lastActionPrefix }}:
                      <span class="font-medium text-neutral-700 dark:text-neutral-200">
                        {{ source.lastActionValue }}
                      </span>
                    </p>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">
                      Cache status:
                      <span
                        class="font-medium"
                        :class="source.hasCache ? 'text-neutral-700 dark:text-neutral-200' : 'text-neutral-500 dark:text-neutral-400'"
                      >
                        {{ source.cacheLabel }}
                      </span>
                    </p>
                    <p v-if="source.totalCountLabel" class="text-xs text-neutral-500 dark:text-neutral-400">
                      {{ source.totalCountLabel }}
                    </p>
                  </div>
                  <div v-if="adminActionsVisible" class="flex flex-wrap items-center gap-2">
                    <template v-if="source.supportsImport && source.importKey">
                      <UButton
                        size="sm"
                        color="primary"
                        variant="soft"
                        icon="i-lucide-cloud-download"
                        :disabled="importing || adminActionsDisabled"
                        :aria-label="`Fetch latest ${source.label}`"
                        @click="() => handleImport(source.importKey as ImportTaskKey)"
                      >
                        Fetch latest
                      </UButton>
                      <UButton
                        v-if="source.supportsIncremental"
                        size="sm"
                        color="success"
                        variant="soft"
                        icon="i-lucide-sparkles"
                        :disabled="importing || adminActionsDisabled"
                        :aria-label="`Run incremental ${source.label.toLowerCase()} update`"
                        @click="() => handleIncrementalImport(source.importKey as ImportTaskKey)"
                      >
                        Incremental update
                      </UButton>
                      <UButton
                        size="sm"
                        color="neutral"
                        variant="ghost"
                        icon="i-lucide-hard-drive-download"
                        :disabled="importing || adminActionsDisabled || !source.hasCache"
                        :aria-label="`Use cached ${source.label}`"
                        @click="() => handleCachedReimport(source.importKey as ImportTaskKey)"
                      >
                        Use cached feed
                      </UButton>
                    </template>
                    <p
                      v-else
                      class="text-xs text-neutral-500 dark:text-neutral-400"
                    >
                      Refreshed automatically during catalog imports.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div v-if="adminActionsVisible" class="flex flex-1 flex-wrap gap-2">
                <UButton
                  color="primary"
                  icon="i-lucide-cloud-download"
                  :loading="importing"
                  :disabled="importing || adminActionsDisabled"
                  @click="() => handleImport()"
                >
                  {{ importing ? "Importing…" : "Import latest data" }}
                </UButton>
                <UButton
                  color="success"
                  variant="soft"
                  icon="i-lucide-sparkles"
                  :disabled="importing || adminActionsDisabled"
                  @click="() => handleIncrementalImport()"
                >
                  Run incremental update for all
                </UButton>
                <UButton
                  color="neutral"
                  variant="soft"
                  icon="i-lucide-refresh-ccw"
                  :disabled="importing || adminActionsDisabled"
                  @click="() => handleCachedReimport()"
                >
                  Reimport cached data
                </UButton>
                <UButton
                  color="neutral"
                  variant="soft"
                  icon="i-lucide-layers"
                  :loading="reclassifyingCatalog"
                  :disabled="importing || resettingDatabase || reclassifyingCatalog || isClassificationRunning || adminActionsDisabled"
                  @click="handleReclassify"
                >
                  {{ reclassifyingCatalog ? "Reclassifying…" : "Reclassify cached data" }}
                </UButton>
                <UButton
                  color="error"
                  variant="soft"
                  icon="i-lucide-trash"
                  :loading="resettingDatabase"
                  :disabled="importing || resettingDatabase || reclassifyingCatalog || isClassificationRunning || adminActionsDisabled"
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
                  <div v-if="formattedImportEvents.length" class="mt-3 space-y-2">
                    <p class="text-[0.65rem] uppercase tracking-wide text-neutral-400 dark:text-neutral-500">
                      Recent activity
                    </p>
                    <div
                      v-for="event in formattedImportEvents"
                      :key="event.id"
                      class="rounded-md border border-neutral-200/80 bg-white/70 p-2 text-[0.72rem] dark:border-neutral-800 dark:bg-neutral-900/40"
                    >
                      <div class="flex items-start justify-between gap-3">
                        <div class="space-y-1">
                          <p class="font-medium text-neutral-700 dark:text-neutral-100">
                            {{ event.taskLabel ?? 'Catalog import' }}
                          </p>
                          <p class="text-[0.68rem] text-neutral-500 dark:text-neutral-400">
                            {{ event.message }}
                          </p>
                        </div>
                        <UBadge :color="event.badgeVariant" variant="soft" class="shrink-0 text-[0.65rem]">
                          {{ eventStatusLabels[event.status] ?? 'Status' }}
                        </UBadge>
                      </div>
                      <p class="mt-1 text-[0.65rem] text-neutral-400 dark:text-neutral-500">
                        {{ event.timestampLabel }}
                      </p>
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
      </div>
    </UPageBody>
  </UPage>
</template>
