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
    label: "My software",
    to: "/settings/software",
    icon: "i-lucide-monitor-cog",
    active: route.path.startsWith("/settings/software"),
  },
  {
    label: "Market intel",
    to: "/market-intel",
    icon: "i-lucide-dollar-sign",
    active: route.path === "/market-intel",
  },
  {
    label: "Settings",
    to: "/settings",
    icon: "i-lucide-sliders",
    active: route.path === "/settings",
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
    <UHeader
      title="In the Wild"
      to="/"
      :ui="{ container: 'max-w-none w-full mx-0 px-4 sm:px-6' }"
    >
      <template #title>
        <span class="inline-flex items-center gap-2">
          <img
            src="/apple-touch-icon.png"
            alt="In the Wild logo"
            class="h-6 w-6"
          />
          <span>In the Wild</span>
        </span>
      </template>
      <UNavigationMenu :items="navigationItems" />
      <template #right>
     <UColorModeButton />
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
