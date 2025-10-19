<script setup lang="ts">
import { computed } from "vue";
import type { KevEntry, KevEntrySummary } from "~/types";

type SourceBadgeMap = Record<
  KevEntrySummary["sources"][number],
  { label: string; color: string }
>;

type CvssSeverity = Exclude<KevEntrySummary["cvssSeverity"], null>;

const props = defineProps<{
  open: boolean;
  entry: KevEntry | null;
  loading: boolean;
  error: string | null;
  sourceBadgeMap: SourceBadgeMap;
  cvssSeverityColors: Record<CvssSeverity, string>;
  buildCvssLabel: (severity: KevEntrySummary["cvssSeverity"], score: number | null) => string;
  formatEpssScore: (score: number | null) => string | null;
  formatOptionalTimestamp: (value: string | null) => string;
  getWellKnownCveName: (cveId: string) => string | null;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "close"): void;
}>();

const isOpen = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const handleClose = () => {
  emit("close");
  emit("update:open", false);
};
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
                <UBadge
                  v-for="source in props.entry.sources"
                  :key="source"
                  :color="props.sourceBadgeMap[source]?.color ?? 'neutral'"
                  variant="soft"
                  class="text-xs font-semibold"
                >
                  {{ props.sourceBadgeMap[source]?.label ?? source.toUpperCase() }}
                </UBadge>
              </div>
            </div>
          </template>

          <template #default>
            <div class="space-y-4">
              <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Vendor
                  </p>
                  <p class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                    {{ props.entry.vendor }}
                  </p>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Product
                  </p>
                  <p class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                    {{ props.entry.product }}
                  </p>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Date added
                  </p>
                  <p class="text-base text-neutral-900 dark:text-neutral-100">
                    {{ props.entry.dateAdded }}
                  </p>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Ransomware use
                  </p>
                  <p class="text-base text-neutral-900 dark:text-neutral-100">
                    {{ props.entry.ransomwareUse || 'Not specified' }}
                  </p>
                </div>
                <div class="space-y-1">
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
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Exploited since
                  </p>
                  <p class="text-base text-neutral-900 dark:text-neutral-100">
                    {{ props.formatOptionalTimestamp(props.entry.exploitedSince) }}
                  </p>
                </div>
                <div>
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Last updated
                  </p>
                  <p class="text-base text-neutral-900 dark:text-neutral-100">
                    {{ props.formatOptionalTimestamp(props.entry.dateUpdated) }}
                  </p>
                </div>
              </div>

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
                    <UBadge
                      v-for="category in props.entry.domainCategories"
                      :key="category"
                      color="primary"
                      variant="soft"
                    >
                      {{ category }}
                    </UBadge>
                  </div>
                </div>
                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Exploit profiles
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <UBadge
                      v-for="layer in props.entry.exploitLayers"
                      :key="layer"
                      color="warning"
                      variant="soft"
                    >
                      {{ layer }}
                    </UBadge>
                  </div>
                </div>
                <div class="space-y-2">
                  <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                    Vulnerability categories
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <UBadge
                      v-for="category in props.entry.vulnerabilityCategories"
                      :key="category"
                      color="secondary"
                      variant="soft"
                    >
                      {{ category }}
                    </UBadge>
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
