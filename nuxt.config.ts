// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: "2025-10-28",
  devtools: { enabled: true },
  modules: ["@nuxt/ui", "@nuxthub/core"],
  css: ["~/assets/css/main.css"],
  hub: {
    database: true,
  },
  ignore: [
    'data/**',
    'data/cache/**'
  ],
  ssr: false,
  runtimeConfig: {
    admin: {
      apiKey: process.env.ADMIN_API_KEY ?? "",
    },
    llmAudit: {
      apiUrl: process.env.LLM_AUDIT_API_URL ?? "",
      apiKey: process.env.LLM_AUDIT_API_KEY ?? "",
      orgId: process.env.LLM_AUDIT_ORG_ID ?? "",
      model: process.env.LLM_AUDIT_MODEL ?? "",
      maxEntries: process.env.LLM_AUDIT_MAX_ENTRIES ?? "",
      temperature: process.env.LLM_AUDIT_TEMPERATURE ?? "",
    },
    openai: {
      apiKey: process.env.OPENAI_API_KEY ?? "",
    },
    public: {
      adminCookieName: "admin-access",
    },
  },
  devServer: {
    port: 3001,
  },
  nitro: {
    externals: { external: ['picomatch', 'fast-glob', 'chokidar'] },
    rollupConfig: { external: ['node:path'] },
    preset: 'cloudflare-pages'
  },
  vite: {
    optimizeDeps: {
      exclude: ['picomatch', 'fast-glob']
    }
  }
});
