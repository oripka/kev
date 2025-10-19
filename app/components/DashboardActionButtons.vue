<script setup lang="ts">
import { computed } from "vue";
import type { QuickActionKey } from "~/types/dashboard";

type ButtonVariant = "soft" | "solid";
type ButtonSize = "sm" | "md" | "lg";

type ActionButtonItem = {
  id: QuickActionKey;
  icon: string;
  color: string;
  variant: ButtonVariant;
  size: ButtonSize;
  tooltip: string;
  ariaLabel: string;
};

const props = defineProps<{
  items: ActionButtonItem[];
  orientation?: "vertical" | "horizontal";
  wrapperClass?: string;
}>();

const emit = defineEmits<{
  (event: "select", action: QuickActionKey): void;
}>();

const orientation = computed(() => props.orientation ?? "vertical");

const containerClasses = computed(() => [
  "flex",
  orientation.value === "vertical" ? "flex-col" : "flex-row",
  orientation.value === "vertical" ? "items-stretch" : "items-center",
  orientation.value === "vertical" ? "gap-3" : "gap-2",
  props.wrapperClass,
]);

const tooltipPlacement = computed(() =>
  orientation.value === "vertical" ? "left" : "top"
);

const handleSelect = (action: QuickActionKey) => {
  emit("select", action);
};
</script>

<template>
  <div :class="containerClasses">
    <UTooltip
      v-for="item in props.items"
      :key="item.id"
      :text="item.tooltip"
      :placement="tooltipPlacement"
    >
      <UButton
        :color="item.color"
        :variant="item.variant"
        :size="item.size"
        :icon="item.icon"
        :aria-label="item.ariaLabel"
        @click="handleSelect(item.id)"
      />
    </UTooltip>
  </div>
</template>
