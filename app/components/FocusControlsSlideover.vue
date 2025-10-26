<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  open: boolean;
  trackedProductsReady: boolean;
  showOwnedOnly: boolean;
  showWellKnownOnly: boolean;
  showRansomwareOnly: boolean;
  showInternetExposedOnly: boolean;
  showPublicExploitOnly: boolean;
  trackedProductCount: number;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "update:show-owned-only", value: boolean): void;
  (event: "update:show-well-known-only", value: boolean): void;
  (event: "update:show-ransomware-only", value: boolean): void;
  (event: "update:show-internet-exposed-only", value: boolean): void;
  (event: "update:show-public-exploit-only", value: boolean): void;
}>();

const open = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const showOwnedOnly = computed({
  get: () => props.showOwnedOnly,
  set: (value: boolean) => emit("update:show-owned-only", value),
});

const showWellKnownOnly = computed({
  get: () => props.showWellKnownOnly,
  set: (value: boolean) => emit("update:show-well-known-only", value),
});

const showRansomwareOnly = computed({
  get: () => props.showRansomwareOnly,
  set: (value: boolean) => emit("update:show-ransomware-only", value),
});

const showInternetExposedOnly = computed({
  get: () => props.showInternetExposedOnly,
  set: (value: boolean) => emit("update:show-internet-exposed-only", value),
});

const showPublicExploitOnly = computed({
  get: () => props.showPublicExploitOnly,
  set: (value: boolean) => emit("update:show-public-exploit-only", value),
});
</script>

<template>
  <USlideover
    v-model:open="open"
    title="Focus controls"
    description="Highlight the vulnerabilities that matter most to your organisation."
    :ui="{ content: 'max-w-lg' }"
    :unmount-on-hide="false"
  >
    <template #body>
      <div class="relative space-y-5">
        <div
          v-if="!props.trackedProductsReady"
          class="pointer-events-none absolute inset-0 rounded-xl bg-neutral-200/70 backdrop-blur-sm dark:bg-neutral-800/60"
        />

        <div class="space-y-3">
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">My software</p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Only show CVEs that match the products you track.
              </p>
            </div>
            <USwitch v-model="showOwnedOnly" :disabled="!props.trackedProductsReady" />
          </div>
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Named CVEs</p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Elevate high-profile, widely reported vulnerabilities.
              </p>
            </div>
            <USwitch v-model="showWellKnownOnly" />
          </div>
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Ransomware focus</p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Restrict the view to CVEs linked to ransomware campaigns.
              </p>
            </div>
            <USwitch v-model="showRansomwareOnly" />
          </div>
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Public exploit coverage</p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Surface CVEs with Metasploit modules or published GitHub PoCs.
              </p>
            </div>
            <USwitch v-model="showPublicExploitOnly" />
          </div>
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Internet exposure</p>
              <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Prioritise vulnerabilities likely to be exposed on the open internet.
              </p>
            </div>
            <USwitch v-model="showInternetExposedOnly" />
          </div>
        </div>

        <div class="rounded-lg border border-neutral-200 bg-neutral-50/70 p-4 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/40 dark:text-neutral-300">
          <p class="font-semibold text-neutral-700 dark:text-neutral-100">Tracked products</p>
          <p class="mt-1">{{ props.trackedProductCount.toLocaleString() }} product(s) selected.</p>
          <p class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
            Manage the list on the dashboard at any time; changes are saved automatically.
          </p>
        </div>
      </div>
    </template>
  </USlideover>
</template>
