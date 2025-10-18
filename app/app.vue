<script setup lang="ts">
const route = useRoute()

const links = [
  { label: 'Overview', to: '/' },
  { label: 'Catalog', to: '/list' },
  { label: 'Statistics', to: '/stats' },
  { label: 'Categories', to: '/categories' }
]
</script>

<template>
  <UApp>
    <NuxtRouteAnnouncer />
    <NuxtLoadingIndicator />
    <UNotifications />

    <UAppShell>
      <template #header>
        <UContainer>
          <UHorizontalNavigation :links="links" :value="route.path" />
        </UContainer>
      </template>

      <template #default>
        <UContainer>
          <NuxtPage />
        </UContainer>
      </template>
    </UAppShell>
  </UApp>
</template>
