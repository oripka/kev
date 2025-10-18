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
      <UText>
        <UIcon v-if="props.icon" :name="props.icon" />
        {{ props.title }}
      </UText>
    </template>
    <template #body>
      <UText>{{ props.value }}</UText>
      <UText v-if="props.description" color="neutral" variant="subtle">{{ props.description }}</UText>
    </template>
  </UCard>
</template>
