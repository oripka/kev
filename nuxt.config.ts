// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  modules: ['@nuxt/ui', '@nuxthub/core'],
  css: ['~/assets/css/main.css'],
  runtimeConfig: {
    llmAudit: {
      apiUrl: process.env.LLM_AUDIT_API_URL ?? '',
      apiKey: process.env.LLM_AUDIT_API_KEY ?? '',
      orgId: process.env.LLM_AUDIT_ORG_ID ?? '',
      model: process.env.LLM_AUDIT_MODEL ?? '',
      maxEntries: process.env.LLM_AUDIT_MAX_ENTRIES ?? '',
    },
    openai: {
      apiKey: process.env.OPENAI_API_KEY ?? '',
    },
  },
  devServer: {
    port: 3001,
  },
})
