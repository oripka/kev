<script setup lang="ts">
import { computed } from "vue";
import type { NavigationMenuItem } from "@nuxt/ui";

const route = useRoute();

const navigationItems = computed<NavigationMenuItem[]>(() => [
  {
    label: "Catalog",
    to: "/",
    icon: "i-lucide-layers",
    active: route.path === "/",
  },
  {
    label: "Last 14 days",
    to: "/vulns-last-two-weeks",
    icon: "i-lucide-hourglass",
    active: route.path === "/vulns-last-two-weeks",
  },
  {
    label: "Market intel",
    to: "/market-intel",
    icon: "i-lucide-dollar-sign",
    active: route.path === "/market-intel",
  },
  {
    label: "My software",
    to: "/settings/software",
    icon: "i-lucide-monitor-cog",
    active: route.path.startsWith("/settings/software"),
  },
  {
    label: "Admin",
    to: "/admin",
    icon: "i-lucide-bar-chart-3",
    active: route.path === "/admin",
  },
]);
</script>

<template>
  <UApp>
    <NuxtRouteAnnouncer />
    <NuxtLoadingIndicator />
    <UToaster />
    <UHeader title="In the Wild" to="/">
      <UNavigationMenu :items="navigationItems" />
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
