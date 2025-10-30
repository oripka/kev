<script setup lang="ts">
import { computed } from "vue";
import { useHead } from "#imports";
import { focusTopics } from "~/constants/focusTopics";
import FocusTopicCard from "~/components/FocusTopicCard.vue";

const sortedTopics = computed(() =>
  [...focusTopics].sort((a, b) => a.title.localeCompare(b.title)),
);

const topicCards = computed(() =>
  sortedTopics.value.map((topic) => ({
    topic,
    badgeColor: topic.category === "critical" ? "rose" : "sky",
    badgeLabel: topic.category === "critical" ? "Critical" : "Focus",
    icon: topic.icon ?? (topic.category === "critical" ? "i-lucide-flame" : "i-lucide-compass"),
  })),
);

useHead({
  title: "Focus pages",
  meta: [
    {
      name: "description",
      content:
        "Curated KEV focus pages combine narrative context, metrics, and pre-filtered vulnerability lists for high-impact remediation themes.",
    },
  ],
});
</script>

<template>
  <UContainer class="py-12 space-y-14">
    <section class="space-y-6">
      <div class="flex flex-wrap items-center gap-3">
        <UBadge color="primary" variant="soft" class="font-semibold">Focus playbooks</UBadge>
      </div>
      <div class="space-y-4">
        <h1 class="text-3xl font-bold text-neutral-900 dark:text-neutral-50">
          Translate KEV data into action-ready focus pages
        </h1>
        <p class="text-lg text-neutral-600 dark:text-neutral-300">
          Each page packages narrative context, curated metrics, and shareable filters so response teams understand why a theme matters, how often it is exploited, and what to do next.
        </p>
      </div>
    </section>

    <section class="space-y-6">
      <div class="flex items-center justify-between gap-4">
        <div>
          <h2 class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
            Curated focus pages
          </h2>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Explore in-the-wild hotspots across web servers, browsers, edge gateways, and client software without juggling overlapping narratives.
          </p>
        </div>
      </div>
      <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
        <ULink
          v-for="card in topicCards"
          :key="card.topic.slug"
          :to="{ path: `/focus/${card.topic.slug}` }"
          class="block"
        >
          <FocusTopicCard
            :topic="card.topic"
            :badge-color="card.badgeColor"
            :badge-label="card.badgeLabel"
            :icon="card.icon"
            class="h-full"
          />
        </ULink>
      </div>
    </section>
  </UContainer>
</template>
