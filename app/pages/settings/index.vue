<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { FetchError } from "ofetch";
import type { TableColumn } from "@nuxt/ui";
import {
  areQuickFilterSummaryConfigsEqual,
  cloneQuickFilterSummaryConfig,
  defaultQuickFilterSummaryConfig,
  normaliseQuickFilterSummaryConfig,
  quickFilterSummaryMetricInfo,
  quickFilterSummaryMetricOrder,
} from "~/utils/quickFilterSummaryConfig";
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

const numberFormatter = new Intl.NumberFormat("en-US");

const {
  data,
  pending,
  error,
  refresh: refreshAdminSoftware,
} = await useFetch<AdminSoftwareResponse>("/api/admin/software", {
  default: () => ({
    totals: {
      sessions: 0,
      trackedSelections: 0,
      uniqueProducts: 0,
      uniqueVendors: 0,
    },
    products: [],
    vendors: [],
  }),
});

const resolveStatusCode = (fetchError: FetchError<unknown> | null) => {
  if (!fetchError) {
    return null;
  }

  const candidate = fetchError as FetchError<unknown> & {
    statusCode?: number;
    status?: number;
    data?: unknown;
  };

  if (typeof candidate.statusCode === "number") {
    return candidate.statusCode;
  }

  if (typeof candidate.status === "number") {
    return candidate.status;
  }

  if (
    candidate.data &&
    typeof candidate.data === "object" &&
    "statusCode" in candidate.data &&
    typeof (candidate.data as { statusCode?: number }).statusCode === "number"
  ) {
    return (candidate.data as { statusCode?: number }).statusCode ?? null;
  }

  return null;
};

const adminAccessForbidden = computed(() => resolveStatusCode(error.value) === 403);

const hasAdminAccess = computed(() => !adminAccessForbidden.value && !error.value);

const adminStatsLoadError = computed(() => {
  if (!error.value || adminAccessForbidden.value) {
    return null;
  }

  return error.value;
});

const totals = computed(() => data.value?.totals ?? {
  sessions: 0,
  trackedSelections: 0,
  uniqueProducts: 0,
  uniqueVendors: 0,
});

const productStats = computed(() => data.value?.products ?? []);
const vendorStats = computed(() => data.value?.vendors ?? []);

const productColumns = computed<TableColumn<ProductStat>[]>(() => [
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
]);

const vendorColumns = computed<TableColumn<VendorStat>[]>(() => [
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
]);

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

const canManageQuickFilterSummary = computed(() => hasAdminAccess.value);

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

watch(hasAdminAccess, (value) => {
  if (value) {
    quickFilterSummarySaveError.value = null;
  }
});

const disableMetricToggle = (key: QuickFilterSummaryMetricKey) => {
  const metrics = quickFilterSummaryForm.value.metrics;
  return metrics.length === 1 && metrics.includes(key);
};

const toggleQuickFilterSummaryMetric = (
  key: QuickFilterSummaryMetricKey,
  selected: boolean,
) => {
  if (!canManageQuickFilterSummary.value) {
    return;
  }
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
  if (!canManageQuickFilterSummary.value) {
    return;
  }
  quickFilterSummaryForm.value.showActiveFilterChips = value;
};

const setShowQuickFilterResetButton = (value: boolean) => {
  if (!canManageQuickFilterSummary.value) {
    return;
  }
  quickFilterSummaryForm.value.showResetButton = value;
};

const restoreQuickFilterSummaryDefaults = () => {
  if (!canManageQuickFilterSummary.value) {
    return;
  }
  quickFilterSummaryForm.value = cloneQuickFilterSummaryConfig(
    defaultQuickFilterSummaryConfig,
  );
};

const saveQuickFilterSummaryConfig = async () => {
  if (!canManageQuickFilterSummary.value) {
    quickFilterSummarySaveError.value = "Admin access required to update settings";
    return;
  }
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

const adminApiKey = ref("");
const adminLoginPending = ref(false);
const adminLoginError = ref<string | null>(null);
const adminLoginSuccess = ref(false);

const submitAdminApiKey = async () => {
  if (!adminApiKey.value.trim()) {
    adminLoginError.value = "Enter the admin API key to continue";
    return;
  }

  adminLoginPending.value = true;
  adminLoginError.value = null;
  adminLoginSuccess.value = false;

  try {
    await $fetch("/api/admin/session", {
      method: "POST",
      body: { key: adminApiKey.value.trim() },
    });

    adminLoginSuccess.value = true;
    adminApiKey.value = "";
    await refreshAdminSoftware();
  } catch (exception) {
    adminLoginError.value =
      exception instanceof Error
        ? exception.message
        : "Unable to verify admin API key";
  } finally {
    adminLoginPending.value = false;
  }
};
</script>

<template>
  <UPage>
    <UPageBody>
      <div class="mx-auto grid w-full max-w-6xl gap-4 px-6">
        <UCard v-if="hasAdminAccess">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                  Settings overview
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  Adjust catalog defaults and review saved filter usage.
                </p>
              </div>
              <UButton
                color="primary"
                icon="i-lucide-monitor-cog"
                to="/settings/software"
              >
                Manage tracked software
              </UButton>
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
            v-if="adminStatsLoadError"
            color="error"
            variant="soft"
            title="Unable to load usage data"
            :description="adminStatsLoadError.message"
            class="mt-4"
          />
          <p
            v-else-if="pending"
            class="mt-4 text-sm text-neutral-500 dark:text-neutral-400"
          >
            Loading saved filter analytics…
          </p>
        </UCard>

        <UCard v-else-if="adminAccessForbidden">
          <template #header>
            <div class="space-y-1">
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Unlock admin controls
              </p>
              <p class="text-sm text-neutral-500 dark:text-neutral-400">
                Enter the admin API key to access usage analytics and global preferences.
              </p>
            </div>
          </template>

          <form class="space-y-4" @submit.prevent="submitAdminApiKey">
            <UFormField label="Admin API key" required>
              <UInput
                v-model="adminApiKey"
                type="password"
                autocomplete="off"
                placeholder="Enter the API key"
              />
            </UFormField>

            <div class="flex flex-wrap items-center gap-3">
              <UButton type="submit" color="primary" :loading="adminLoginPending">
                Unlock settings
              </UButton>

              <span
                v-if="adminLoginPending"
                class="text-sm text-neutral-500 dark:text-neutral-400"
              >
                Verifying…
              </span>
            </div>
          </form>

          <UAlert
            v-if="adminLoginError"
            color="error"
            variant="soft"
            class="mt-4"
            icon="i-lucide-alert-triangle"
            :description="adminLoginError"
          />

          <UAlert
            v-else-if="adminLoginSuccess"
            color="success"
            variant="soft"
            class="mt-4"
            icon="i-lucide-badge-check"
            title="Admin controls unlocked"
            description="Usage analytics and admin settings are now available."
          />
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
          <UAlert
            v-else-if="adminAccessForbidden"
            color="neutral"
            variant="soft"
            icon="i-lucide-lock"
            title="Admin access required"
            description="Unlock admin controls above to change the default quick filter summary."
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
                    :disabled="disableMetricToggle(metric.key) || !canManageQuickFilterSummary"
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
                  :disabled="!canManageQuickFilterSummary"
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
                  :disabled="!canManageQuickFilterSummary"
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
                  :disabled="!canManageQuickFilterSummary || !quickFilterSummaryCanRestore || quickFilterSummarySaving"
                  @click="restoreQuickFilterSummaryDefaults"
                >
                  Restore defaults
                </UButton>
                <UButton
                  color="primary"
                  :loading="quickFilterSummarySaving"
                  :disabled="!canManageQuickFilterSummary || !quickFilterSummaryCanSave"
                  @click="saveQuickFilterSummaryConfig"
                >
                  Save changes
                </UButton>
              </div>
            </div>
          </div>
        </UCard>

        <div v-if="hasAdminAccess" class="grid gap-4 md:grid-cols-2">
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
      </div>
    </UPageBody>
  </UPage>
</template>
