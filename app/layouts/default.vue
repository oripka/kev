<script setup lang="ts">
const navigationLinks = [
  {
    label: 'Dashboard',
    to: '/',
    icon: 'i-lucide-layout-dashboard'
  },
  {
    label: 'KEV Table',
    to: '/list',
    icon: 'i-lucide-table'
  },
  {
    label: 'Statistics',
    to: '/stats',
    icon: 'i-lucide-chart-bar'
  }
]
</script>

<template>
  <UContainer>
    <header>
      <UCard>
        <template #header>
          <strong>KEV Watch</strong>
        </template>
        <template #body>
          <UHorizontalNavigation :links="navigationLinks" />
        </template>
      </UCard>
    </header>

    <main>
      <slot />
    </main>

    <footer>
      <UText color="neutral" variant="subtle">
        Data from the CISA Known Exploited Vulnerabilities Catalog.
      </UText>
    </footer>
  </UContainer>
</template>
