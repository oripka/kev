<script setup lang="ts">
const props = defineProps<{
  label: string;
  value: string;
  description: string;
  caption?: string;
}>();
</script>

<template>
  <UCard>
    <div class="space-y-2">
      <p class="text-xs font-semibold uppercase tracking-wide text-primary-600 dark:text-primary-300">
        {{ props.label }}
      </p>
      <p class="text-3xl font-semibold text-neutral-900 dark:text-neutral-50">
        {{ props.value }}
      </p>
      <p v-if="props.caption" class="text-xs text-neutral-500 dark:text-neutral-400">
        {{ props.caption }}
      </p>
      <p class="text-sm text-neutral-600 dark:text-neutral-300">
        {{ props.description }}
      </p>
    </div>
  </UCard>
</template>
