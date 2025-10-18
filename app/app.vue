<script setup lang="ts">
import { computed } from 'vue'
import type { NavigationMenuItem } from '@nuxt/ui'

const route = useRoute()

const navigationItems = computed<NavigationMenuItem[]>(() => [
  {
    label: 'Overview',
    to: '/',
    icon: 'i-lucide-layout-dashboard',
    active: route.path === '/'
  },
  {
    label: 'Catalog',
    to: '/list',
    icon: 'i-lucide-table',
    active: route.path.startsWith('/list')
  },
  {
    label: 'Statistics',
    to: '/stats',
    icon: 'i-lucide-chart-bar',
    active: route.path.startsWith('/stats')
  },
  {
    label: 'Categories',
    to: '/categories',
    icon: 'i-lucide-layers',
    active: route.path.startsWith('/categories')
  }
])
</script>

<template>
  <UApp>
    <NuxtRouteAnnouncer />
    <NuxtLoadingIndicator />
    <UToaster />

    <UHeader title="KEV Watch" to="/">
      <template #right>
        <UNavigationMenu :items="navigationItems" />
      </template>
    </UHeader>

    <UMain>
      <NuxtLayout>
        <NuxtPage />
      </NuxtLayout>
    </UMain>

    <UFooter>
      <template #left>
        <p class="text-sm text-neutral-500 dark:text-neutral-400">
          Data from the CISA Known Exploited Vulnerabilities Catalog.
        </p>
      </template>
    </UFooter>
  </UApp>
</template>
