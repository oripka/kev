<script setup lang="ts">
import { computed } from "vue";
import type { TrackedProduct } from "~/types";

const props = defineProps<{
  open: boolean;
  trackedProductsReady: boolean;
  showOwnedOnly: boolean;
  trackedProducts: TrackedProduct[];
  trackedProductCount: number;
  hasTrackedProducts: boolean;
  saving: boolean;
  saveError: string | null;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "update:show-owned-only", value: boolean): void;
  (event: "remove", productKey: string): void;
  (event: "clear"): void;
}>();

const open = computed({
  get: () => props.open,
  set: (value: boolean) => emit("update:open", value),
});

const showOwnedOnly = computed({
  get: () => props.showOwnedOnly,
  set: (value: boolean) => emit("update:show-owned-only", value),
});

const handleRemove = (productKey: string) => {
  emit("remove", productKey);
};

const handleClear = () => {
  emit("clear");
};
</script>

<template>
  <USlideover
    v-model:open="open"
    title="My software focus"
    description="Adjust tracked products and the owned-only view without leaving the table."
    :ui="{ content: 'max-w-3xl' }"
    :unmount-on-hide="false"
  >
    <template #body>
      <div class="relative">
        <div
          v-if="!props.trackedProductsReady"
          class="pointer-events-none absolute inset-0 rounded-xl bg-neutral-200/70 backdrop-blur-sm dark:bg-neutral-800/60"
        />
        <TrackedSoftwareSummary
          v-model="showOwnedOnly"
          :tracked-products="props.trackedProducts"
          :tracked-product-count="props.trackedProductCount"
          :has-tracked-products="props.hasTrackedProducts"
          :saving="props.saving"
          :save-error="props.saveError"
          @remove="handleRemove"
          @clear="handleClear"
        />
      </div>
    </template>
  </USlideover>
</template>
