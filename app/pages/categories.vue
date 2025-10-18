<script setup lang="ts">
import { computed, h, reactive, ref, resolveComponent, watch } from "vue";
import { format, parseISO } from "date-fns";
import type { SelectMenuItem, TableColumn } from "@nuxt/ui";
import { useKevData } from "~/composables/useKevData";
import type { KevEntry } from "~/types";

const {
  entries,
  categoryNames,
  vulnerabilityTypeNames,
} = useKevData();

type SelectValue = SelectMenuItem<string> | string | null;

const filters = reactive({
  domain: null as SelectValue,
  vulnerability: null as SelectValue,
  text: "",
});

const toSelectItems = (
  counts: { name: string; count: number }[],
  names: string[]
): SelectMenuItem<string>[] => {
  const formatted = counts.map(({ name, count }) => ({
    label: `${name} (${count})`,
    value: name,
  }));

  const seen = new Set(counts.map((item) => item.name));

  for (const name of names) {
    if (!seen.has(name)) {
      formatted.push({ label: name, value: name });
    }
  }

  return formatted;
};

const computeCounts = (
  items: KevEntry[],
  accessor: (entry: KevEntry) => string | string[]
) => {
  const totals = new Map<string, number>();

  for (const entry of items) {
    const value = accessor(entry);
    const keys = Array.isArray(value) ? value : [value];

    for (const key of keys) {
      if (!key || key === "Other") {
        continue;
      }

      totals.set(key, (totals.get(key) ?? 0) + 1);
    }
  }

  return Array.from(totals.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
};

const UBadge = resolveComponent("UBadge");
const UButton = resolveComponent("UButton");

const showDetails = ref(false);
const detailEntry = ref<KevEntry | null>(null);

const openDetails = (entry: KevEntry) => {
  detailEntry.value = entry;
  showDetails.value = true;
};

const closeDetails = () => {
  showDetails.value = false;
};

watch(showDetails, (value) => {
  if (!value) {
    detailEntry.value = null;
  }
});

const resolveSelectedValue = (value: SelectValue) => {
  if (!value) {
    return null;
  }

  if (typeof value === "string") {
    return value;
  }

  return value.value ?? value.label ?? null;
};

const results = computed(() => {
  const term = filters.text.trim().toLowerCase();
  const domain = resolveSelectedValue(filters.domain);
  const vulnerability = resolveSelectedValue(filters.vulnerability);

  return entries.value.filter((entry) => {
    if (
      domain &&
      !entry.domainCategories.includes(
        domain as (typeof entry.domainCategories)[number]
      )
    ) {
      return false;
    }

    if (
      vulnerability &&
      !entry.vulnerabilityCategories.includes(
        vulnerability as (typeof entry.vulnerabilityCategories)[number]
      )
    ) {
      return false;
    }

    if (term) {
      const text =
        `${entry.cveId} ${entry.vendor} ${entry.product} ${entry.vulnerabilityName}`.toLowerCase();
      if (!text.includes(term)) {
        return false;
      }
    }

    return true;
  });
});

const domainCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.domainCategories)
);

const domainItems = computed(() =>
  toSelectItems(domainCounts.value, categoryNames.value)
);

const vulnerabilityCounts = computed(() =>
  computeCounts(results.value, (entry) => entry.vulnerabilityCategories)
);

const vulnerabilityItems = computed(() =>
  toSelectItems(vulnerabilityCounts.value, vulnerabilityTypeNames.value)
);

const columns: TableColumn<KevEntry>[] = [
  {
    id: "summary",
    header: "Description",
    cell: ({ row }) =>
      h("div", { class: "space-y-1" }, [
        h(
          "p",
          {
            class:
              "max-w-xs whitespace-normal break-words font-medium text-neutral-900 dark:text-neutral-100",
          },
          row.original.vulnerabilityName
        ),
        h(
          "p",
          {
            class:
              "text-sm text-neutral-500 dark:text-neutral-400 max-w-xl whitespace-normal break-words text-pretty",
          },
          row.original.description || "No description provided."
        ),
      ]),
  },
  {
    accessorKey: "dateAdded",
    header: "Date added",
    cell: ({ row }) => {
      const parsed = parseISO(row.original.dateAdded);
      return Number.isNaN(parsed.getTime())
        ? row.original.dateAdded
        : format(parsed, "yyyy-MM-dd");
    },
  },
  {
    id: "domain",
    header: "Domain",
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex flex-wrap gap-2" },
        row.original.domainCategories.map((category) =>
          h(UBadge, { color: "primary", variant: "soft" }, () => category)
        )
      ),
  },
  {
    id: "type",
    header: "Type",
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex flex-wrap gap-2" },
        row.original.vulnerabilityCategories.map((category) =>
          h(UBadge, { color: "secondary", variant: "soft" }, () => category)
        )
      ),
  },
  {
    id: "actions",
    header: "",
    enableSorting: false,
    cell: ({ row }) =>
      h(
        "div",
        { class: "flex justify-end" },
        h(UButton, {
          icon: "i-lucide-eye",
          color: "neutral",
          variant: "ghost",
          "aria-label": `View ${row.original.cveId} details`,
          onClick: () => openDetails(row.original),
        })
      ),
  },
];
</script>

<template>
  <UPage>
    <UPageHeader
      title="Category explorer"
      description="Combine domain and vulnerability categories to focus on what matters"
    />

    <UPageBody>
      <div class="grid grid-cols-1 gap-3 max-w-7xl mx-auto">
        <UCard>
          <template #header>
            <p
              class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
            >
              Filters
            </p>
          </template>

          <div class="grid gap-2 md:grid-cols-2">
            <UFormField class="w-full" label="Domain category">
              <USelectMenu
                class="w-full"
                v-model="filters.domain"
                :items="domainItems"
                clearable
                searchable
              />
            </UFormField>

            <UFormField class="w-full" label="Vulnerability category">
              <USelectMenu
                class="w-full"
                v-model="filters.vulnerability"
                :items="vulnerabilityItems"
                clearable
                searchable
              />
            </UFormField>

            <UFormField label="Search" class="w-full md:col-span-2">
              <UInput
                class="w-full"
                v-model="filters.text"
                placeholder="Filter by CVE, vendor, or product"
              />
            </UFormField>

            <div
              v-if="filters.domain || filters.vulnerability || filters.text"
              class="md:col-span-2"
            >
              <UAlert
                color="info"
                variant="soft"
                icon="i-lucide-filters"
                :title="`${results.length} matching vulnerabilities`"
              />
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <p
              class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
            >
              Results
            </p>
          </template>

          <UTable :data="results" :columns="columns" />
        </UCard>
      </div>

      <UModal
        v-model:open="showDetails"
        :ui="{
          content: 'w-full max-w-7xl rounded-xl shadow-lg',
          body: 'p-6 text-base text-muted',
        }"
      >
        <template #body>
          <UCard v-if="detailEntry">
            <template #header>
              <div class="space-y-1">
                <p
                  class="text-lg font-semibold text-neutral-900 dark:text-neutral-50"
                >
                  {{ detailEntry.vulnerabilityName }}
                </p>
                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                  {{ detailEntry.cveId }}
                </p>
              </div>
            </template>

            <template #default>
              <div class="space-y-4">
                <div class="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Vendor
                    </p>
                    <p
                      class="text-base font-semibold text-neutral-900 dark:text-neutral-100"
                    >
                      {{ detailEntry.vendor }}
                    </p>
                  </div>
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Product
                    </p>
                    <p
                      class="text-base font-semibold text-neutral-900 dark:text-neutral-100"
                    >
                      {{ detailEntry.product }}
                    </p>
                  </div>
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Date added
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.dateAdded }}
                    </p>
                  </div>
                  <div>
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Ransomware use
                    </p>
                    <p class="text-base text-neutral-900 dark:text-neutral-100">
                      {{ detailEntry.ransomwareUse || "Not specified" }}
                    </p>
                  </div>
                </div>

                <div class="space-y-2">
                  <p
                    class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                  >
                    Description
                  </p>
                  <p
                    class="text-sm leading-relaxed text-neutral-600 dark:text-neutral-300"
                  >
                    {{ detailEntry.description || "No description provided." }}
                  </p>
                </div>

                <div class="grid gap-3 sm:grid-cols-2">
                  <div class="space-y-2">
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Domain categories
                    </p>
                    <div class="flex flex-wrap gap-2">
                      <UBadge
                        v-for="category in detailEntry.domainCategories"
                        :key="category"
                        color="primary"
                        variant="soft"
                      >
                        {{ category }}
                      </UBadge>
                    </div>
                  </div>
                  <div class="space-y-2">
                    <p
                      class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                    >
                      Vulnerability categories
                    </p>
                    <div class="flex flex-wrap gap-2">
                      <UBadge
                        v-for="category in detailEntry.vulnerabilityCategories"
                        :key="category"
                        color="secondary"
                        variant="soft"
                      >
                        {{ category }}
                      </UBadge>
                    </div>
                  </div>
                </div>

                <div v-if="detailEntry.notes.length" class="space-y-2">
                  <p
                    class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
                  >
                    Notes
                  </p>
                  <ul
                    class="list-disc space-y-1 pl-4 text-sm text-neutral-600 dark:text-neutral-300"
                  >
                    <li v-for="note in detailEntry.notes" :key="note">
                      {{ note }}
                    </li>
                  </ul>
                </div>
              </div>
            </template>

            <template #footer>
              <div class="flex justify-end gap-2">
                <UButton color="neutral" variant="soft" @click="closeDetails">
                  Close
                </UButton>
              </div>
            </template>
          </UCard>
        </template>
      </UModal>
    </UPageBody>
  </UPage>
</template>
