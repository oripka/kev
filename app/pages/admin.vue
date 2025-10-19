<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { format, parseISO } from "date-fns";
import type { TableColumn } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import type { ClassificationProgress } from "~/types";

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

const totals = computed(() => data.value?.totals ?? {
  sessions: 0,
  trackedSelections: 0,
  uniqueProducts: 0,
  uniqueVendors: 0,
});

const productStats = computed(() => data.value?.products ?? []);
const vendorStats = computed(() => data.value?.vendors ?? []);

const numberFormatter = new Intl.NumberFormat("en-US");

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

const formatTimestamp = (value: string) => {
  const parsed = parseISO(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return format(parsed, "yyyy-MM-dd HH:mm");
};

const catalogUpdatedAt = computed(() => {
  const summary = lastImportSummary.value;
  if (summary) {
    return formatTimestamp(summary.importedAt);
  }
  return updatedAt.value ? formatTimestamp(updatedAt.value) : "Not imported yet";
});

const handleImport = async () => {
  await importLatest({ mode: "force" });
};

const handleCachedReimport = async () => {
  await importLatest({ mode: "cache" });
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
  if (phase === "saving" || phase === "savingEnisa") {
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

const totalCachedEntries = computed(() => totalEntries.value);

const importSummaryMessage = computed(() => {
  const summary = lastImportSummary.value;
  if (!summary) {
    return null;
  }

  const importedAt = formatTimestamp(summary.importedAt);
  const kevCount = summary.kevImported.toLocaleString();
  const enisaCount = summary.enisaImported.toLocaleString();
  const enisaDetail = summary.enisaImported
    ? ` Latest ENISA update: ${
        summary.enisaLastUpdated ? formatTimestamp(summary.enisaLastUpdated) : "not provided"
      }.`
    : "";

  return `Imported ${kevCount} CISA KEV entries and ${enisaCount} ENISA entries from the ${summary.dateReleased} release (${summary.catalogVersion}) on ${importedAt}.${enisaDetail}`;
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

            <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div class="flex flex-1 flex-wrap gap-2">
                <UButton
                  color="primary"
                  icon="i-lucide-cloud-download"
                  :loading="importing"
                  :disabled="importing"
                  @click="handleImport"
                >
                  {{ importing ? "Importing…" : "Import latest data" }}
                </UButton>
                <UButton
                  color="neutral"
                  variant="soft"
                  icon="i-lucide-refresh-ccw"
                  :disabled="importing"
                  @click="handleCachedReimport"
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
                  icon="i-lucide-database-off"
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
