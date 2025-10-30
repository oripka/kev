<script setup lang="ts">
import { computed } from "vue";
import { useHead } from "#imports";
import { focusTopics } from "~/constants/focusTopics";

const sortedTopics = computed(() =>
  [...focusTopics].sort((a, b) => a.title.localeCompare(b.title)),
);

const criticalTopics = computed(() =>
  sortedTopics.value.filter((topic) => topic.category === "critical"),
);

const thematicTopics = computed(() =>
  sortedTopics.value.filter((topic) => topic.category === "theme"),
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
            Critical focus pages
          </h2>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            High-risk exploit themes that demand immediate cross-team coordination.
          </p>
        </div>
      </div>
      <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
        <ULink
          v-for="topic in criticalTopics"
          :key="topic.slug"
          :to="{ path: `/focus/${topic.slug}` }"
        >
          <UCard class="h-full transition hover:border-primary-400">
            <div class="space-y-3">
              <UBadge color="rose" variant="soft" class="font-semibold">Critical</UBadge>
              <h3 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">
                {{ topic.title }}
              </h3>
              <p class="text-sm text-neutral-600 dark:text-neutral-300">
                {{ topic.summary }}
              </p>
              <ul
                v-if="topic.highlightNotes?.length"
                class="list-disc space-y-1 pl-5 text-xs text-neutral-500 dark:text-neutral-400"
              >
                <li v-for="note in topic.highlightNotes" :key="note">
                  {{ note }}
                </li>
              </ul>
            </div>
          </UCard>
        </ULink>
      </div>
    </section>

    <section class="space-y-6">
      <div class="flex items-center justify-between gap-4">
        <div>
          <h2 class="text-2xl font-semibold text-neutral-900 dark:text-neutral-50">
            Operational focus pages
          </h2>
          <p class="text-sm text-neutral-500 dark:text-neutral-400">
            Theme-specific narratives that turn the KEV catalog into shareable playbooks for remediation owners.
          </p>
        </div>
      </div>
      <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
        <ULink
          v-for="topic in thematicTopics"
          :key="topic.slug"
          :to="{ path: `/focus/${topic.slug}` }"
        >
          <UCard class="h-full transition hover:border-primary-400">
            <div class="space-y-3">
              <UBadge color="sky" variant="soft" class="font-semibold">Focus</UBadge>
              <h3 class="text-xl font-semibold text-neutral-900 dark:text-neutral-50">
                {{ topic.title }}
              </h3>
              <p class="text-sm text-neutral-600 dark:text-neutral-300">
                {{ topic.summary }}
              </p>
              <ul
                v-if="topic.additionalInsights?.length"
                class="list-disc space-y-1 pl-5 text-xs text-neutral-500 dark:text-neutral-400"
              >
                <li v-for="note in topic.additionalInsights" :key="note">
                  {{ note }}
                </li>
              </ul>
            </div>
          </UCard>
        </ULink>
      </div>
    </section>
  </UContainer>
</template>
