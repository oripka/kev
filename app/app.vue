<script setup lang="ts">
import { computed } from 'vue'
import type { NavigationMenuItem } from '@nuxt/ui'

const route = useRoute()

const navigationItems = computed<NavigationMenuItem[]>(() => [
  {
    label: 'Categories',
    to: '/',
    icon: 'i-lucide-layers',
    active: route.path === '/'
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
