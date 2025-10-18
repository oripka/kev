<script setup lang="ts">
const props = defineProps<{
  title: string
  value: string
  description?: string
  icon?: string
}>()
</script>

<template>
  <UCard>
    <template #header>
      <p class="flex items-center gap-2 text-base font-medium text-neutral-900 dark:text-neutral-50">
        <UIcon v-if="props.icon" :name="props.icon" />
        {{ props.title }}
      </p>
    </template>
    <template #body>
      <p class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">{{ props.value }}</p>
      <p v-if="props.description" class="text-sm text-neutral-500 dark:text-neutral-400">
        {{ props.description }}
      </p>
    </template>
  </UCard>
</template>
