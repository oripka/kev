import { useLocalStorage } from '@vueuse/core'

type CatalogPreferences = {
  replaceFiltersOnQuickApply: boolean
}

const defaultPreferences: CatalogPreferences = {
  replaceFiltersOnQuickApply: false
}

export const useCatalogPreferences = () =>
  useLocalStorage<CatalogPreferences>('catalog-preferences', defaultPreferences, {
    mergeDefaults: true
  })
