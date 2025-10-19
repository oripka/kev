<script setup lang="ts">
import type { TableColumn } from "@nuxt/ui";

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
