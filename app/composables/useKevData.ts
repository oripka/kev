import { computed, ref, unref, type ComputedRef, type MaybeRef, type Ref } from 'vue'
import type { KevCountDatum, KevEntry, KevResponse } from '~/types'
import { lookupCveName } from '~/utils/cveToNameMap'

type KevQueryParams = Record<string, string | number | boolean | undefined>

type NormalisedQuery = Record<string, string>

type ImportSummary = {
  imported: number
  dateReleased: string
  catalogVersion: string
  importedAt: string
}

type UseKevDataResult = {
  entries: ComputedRef<KevEntry[]>
  counts: ComputedRef<{
    domain: KevCountDatum[]
    exploit: KevCountDatum[]
    vulnerability: KevCountDatum[]
    vendor: KevCountDatum[]
    product: KevCountDatum[]
  }>
  updatedAt: ComputedRef<string>
  catalogBounds: ComputedRef<{ earliest: string | null; latest: string | null }>
  pending: Ref<boolean>
  error: Ref<Error | null>
  refresh: () => Promise<void>
  importLatest: () => Promise<ImportSummary | null>
  importing: Ref<boolean>
  importError: Ref<string | null>
  lastImportSummary: Ref<ImportSummary | null>
  isWellKnownCve: (rawCve: string) => boolean
  getWellKnownCveName: (rawCve: string) => string | undefined
}

type QuerySource = MaybeRef<KevQueryParams | undefined>

type DefaultCounts = KevResponse['counts']

const createDefaultCounts = (): DefaultCounts => ({
  domain: [],
  exploit: [],
  vulnerability: [],
  vendor: [],
  product: []
})

const normaliseQuery = (source?: KevQueryParams): NormalisedQuery => {
  if (!source) {
    return {}
  }

  const query: NormalisedQuery = {}

  for (const [key, value] of Object.entries(source)) {
    if (value === undefined || value === null || value === '') {
      continue
    }

    if (typeof value === 'boolean') {
      query[key] = value ? 'true' : 'false'
    } else {
      query[key] = String(value)
    }
  }

  return query
}

export const useKevData = (querySource?: QuerySource): UseKevDataResult => {
  const normalisedQuery = computed(() => normaliseQuery(querySource ? unref(querySource) : undefined))

  const { data, pending, error, refresh } = useFetch<KevResponse>('/api/kev', {
    query: normalisedQuery,
    watch: [normalisedQuery],
    default: () => ({
      updatedAt: '',
      entries: [],
      counts: createDefaultCounts(),
      catalogBounds: { earliest: null, latest: null }
    })
  })

  const importing = ref(false)
  const importError = ref<string | null>(null)
  const lastImportSummary = ref<ImportSummary | null>(null)

  const importLatest = async () => {
    importing.value = true
    importError.value = null

    try {
      const response = await $fetch<ImportSummary>('/api/fetchKev', {
        method: 'POST'
      })

      lastImportSummary.value = response
      await refresh()
      return response
    } catch (exception) {
      const message =
        exception instanceof Error ? exception.message : 'Unable to import KEV data'
      importError.value = message
      return null
    } finally {
      importing.value = false
    }
  }

  const entries = computed(() => data.value?.entries ?? [])
  const counts = computed(() => data.value?.counts ?? createDefaultCounts())
  const updatedAt = computed(() => data.value?.updatedAt ?? '')
  const catalogBounds = computed(() => data.value?.catalogBounds ?? { earliest: null, latest: null })

  const isWellKnownCve = (rawCve: string) => Boolean(lookupCveName(rawCve))

  const getWellKnownCveName = (rawCve: string) => lookupCveName(rawCve)

  return {
    entries,
    counts,
    updatedAt,
    catalogBounds,
    pending,
    error,
    refresh,
    importLatest,
    importing,
    importError,
    lastImportSummary,
    isWellKnownCve,
    getWellKnownCveName
  }
}
