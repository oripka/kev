import {
  computed,
  onScopeDispose,
  ref,
  unref,
  watch,
  type ComputedRef,
  type MaybeRef,
  type Ref
} from 'vue'
import type { ImportProgress, KevCountDatum, KevEntry, KevResponse } from '~/types'
import { lookupCveName } from '~/utils/cveToNameMap'

type KevQueryParams = Record<string, string | number | boolean | undefined>

type NormalisedQuery = Record<string, string>

type ImportSummary = {
  imported: number
  kevImported: number
  enisaImported: number
  dateReleased: string
  catalogVersion: string
  enisaLastUpdated: string | null
  importedAt: string
}

type ImportMode = 'auto' | 'force' | 'cache'

type ImportOptions = {
  mode?: ImportMode
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
  importLatest: (options?: ImportOptions) => Promise<ImportSummary | null>
  importing: Ref<boolean>
  importError: Ref<string | null>
  lastImportSummary: Ref<ImportSummary | null>
  importProgress: Ref<ImportProgress>
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
  const defaultImportProgress = (): ImportProgress => ({
    phase: 'idle',
    completed: 0,
    total: 0,
    message: '',
    startedAt: null,
    updatedAt: null,
    error: null
  })
  const importProgress = ref<ImportProgress>(defaultImportProgress())
  const isClient = typeof window !== 'undefined'
  let progressTimer: ReturnType<typeof setInterval> | null = null

  const shouldPoll = (phase: ImportProgress['phase']) =>
    phase === 'preparing' ||
    phase === 'fetchingCvss' ||
    phase === 'fetchingEnisa' ||
    phase === 'enriching' ||
    phase === 'saving' ||
    phase === 'savingEnisa'

  const stopProgressPolling = () => {
    if (progressTimer) {
      clearInterval(progressTimer)
      progressTimer = null
    }
  }

  const refreshProgress = async () => {
    try {
      const latest = await $fetch<ImportProgress>('/api/import/progress', {
        headers: {
          'cache-control': 'no-store'
        }
      })
      importProgress.value = latest

      if (!shouldPoll(latest.phase)) {
        stopProgressPolling()
      }
    } catch {
      // Ignore polling errors to avoid interrupting the import flow.
    }
  }

  const startProgressPolling = () => {
    if (!isClient) {
      return
    }

    if (!progressTimer) {
      void refreshProgress()
      progressTimer = setInterval(() => {
        void refreshProgress()
      }, 2_000)
    }
  }

  const importLatest = async (options: ImportOptions = {}) => {
    const mode: ImportMode = options.mode ?? 'auto'
    importing.value = true
    importError.value = null

    try {
      if (isClient) {
        startProgressPolling()
      }

      const response = await $fetch<ImportSummary>('/api/fetchKev', {
        method: 'POST',
        body: { mode }
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
      if (isClient) {
        void refreshProgress().finally(() => {
          if (!shouldPoll(importProgress.value.phase)) {
            stopProgressPolling()
          }
        })
      }
    }
  }

  const entries = computed(() => data.value?.entries ?? [])
  const counts = computed(() => data.value?.counts ?? createDefaultCounts())
  const updatedAt = computed(() => data.value?.updatedAt ?? '')
  const catalogBounds = computed(() => data.value?.catalogBounds ?? { earliest: null, latest: null })

  const isWellKnownCve = (rawCve: string) => Boolean(lookupCveName(rawCve))

  const getWellKnownCveName = (rawCve: string) => lookupCveName(rawCve)

  if (isClient) {
    watch(
      importing,
      value => {
        if (value) {
          startProgressPolling()
        }
      },
      { immediate: true }
    )

    onScopeDispose(() => {
      stopProgressPolling()
    })
  }

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
    importProgress,
    isWellKnownCve,
    getWellKnownCveName
  }
}
