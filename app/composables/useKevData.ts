import {
  computed,
  onScopeDispose,
  ref,
  shallowRef,
  unref,
  watch,
  type ComputedRef,
  type MaybeRef,
  type Ref
} from 'vue'
import type {
  ImportProgress,
  ImportTaskKey,
  KevCountDatum,
  KevEntrySummary,
  KevResponse,
  MarketOverview
} from '~/types'
import { lookupCveName } from '~/utils/cveToNameMap'

type KevQueryParams = Record<string, string | number | boolean | undefined>

type NormalisedQuery = Record<string, string>

type ImportSummary = {
  imported: number
  kevImported: number
  kevNewCount: number
  kevUpdatedCount: number
  kevSkippedCount: number
  kevRemovedCount: number
  kevImportStrategy: ImportStrategy
  historicImported: number
  enisaImported: number
  metasploitImported: number
  metasploitModules: number
  metasploitCommit: string | null
  pocImported: number
  marketImported: number
  marketOfferCount: number
  marketProgramCount: number
  marketProductCount: number
  marketLastCaptureAt: string | null
  marketLastSnapshotAt: string | null
  dateReleased: string
  catalogVersion: string
  enisaLastUpdated: string | null
  importedAt: string
  sources: ImportTaskKey[]
}

type ImportMode = 'auto' | 'force' | 'cache'
type ImportStrategy = 'full' | 'incremental'

type ImportOptions = {
  mode?: ImportMode
  source?: ImportTaskKey | 'all'
  strategy?: ImportStrategy
}

type UseKevDataResult = {
  entries: ComputedRef<KevEntrySummary[]>
  counts: ComputedRef<{
    domain: KevCountDatum[]
    exploit: KevCountDatum[]
    vulnerability: KevCountDatum[]
    vendor: KevCountDatum[]
    product: KevCountDatum[]
  }>
  totalEntries: ComputedRef<number>
  totalEntriesWithoutYear: ComputedRef<number>
  entryLimit: ComputedRef<number>
  updatedAt: ComputedRef<string>
  catalogBounds: ComputedRef<{ earliest: string | null; latest: string | null }>
  market: ComputedRef<MarketOverview>
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

const createDefaultMarketOverview = (): MarketOverview => ({
  priceBounds: { minRewardUsd: null, maxRewardUsd: null },
  filteredPriceBounds: { minRewardUsd: null, maxRewardUsd: null },
  offerCount: 0,
  programCounts: [],
  categoryCounts: []
})

const DEFAULT_ENTRY_LIMIT = 250

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

const areQueriesEqual = (first: NormalisedQuery, second: NormalisedQuery) => {
  const firstKeys = Object.keys(first)
  const secondKeys = Object.keys(second)

  if (firstKeys.length !== secondKeys.length) {
    return false
  }

  return firstKeys.every((key) => first[key] === second[key])
}

export const useKevData = (querySource?: QuerySource): UseKevDataResult => {
  const normalisedQuery = shallowRef<NormalisedQuery>({})

  const resolveQuery = () => normaliseQuery(querySource ? unref(querySource) : undefined)

  watch(
    resolveQuery,
    (next) => {
      if (!areQueriesEqual(normalisedQuery.value, next)) {
        normalisedQuery.value = next
      }
    },
    { immediate: true }
  )

  const { data, pending, error, refresh } = useFetch<KevResponse>('/api/kev', {
    query: normalisedQuery,
    watch: [normalisedQuery],
    default: () => ({
      updatedAt: '',
      entries: [],
      counts: createDefaultCounts(),
      catalogBounds: { earliest: null, latest: null },
      totalEntries: 0,
      totalEntriesWithoutYear: 0,
      entryLimit: DEFAULT_ENTRY_LIMIT,
      market: createDefaultMarketOverview()
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
    error: null,
    activeSources: [],
    tasks: [],
    events: []
  })

  const normaliseImportProgress = (
    progress: Partial<ImportProgress> | undefined
  ): ImportProgress => {
    const base = defaultImportProgress()

    if (!progress) {
      return base
    }

    const tasks = Array.isArray(progress.tasks) ? progress.tasks : []
    const events = Array.isArray(progress.events) ? progress.events : []

    return {
      ...base,
      ...progress,
      tasks,
      events
    }
  }

  const importProgress = ref<ImportProgress>(defaultImportProgress())
  const isClient = typeof window !== 'undefined'
  let progressTimer: ReturnType<typeof setInterval> | null = null

  const shouldPoll = (phase: ImportProgress['phase']) =>
    phase === 'preparing' ||
    phase === 'fetchingCvss' ||
    phase === 'fetchingEnisa' ||
    phase === 'fetchingHistoric' ||
    phase === 'fetchingMetasploit' ||
    phase === 'fetchingPoc' ||
    phase === 'fetchingMarket' ||
    phase === 'enriching' ||
    phase === 'saving' ||
    phase === 'savingEnisa' ||
    phase === 'savingHistoric' ||
    phase === 'savingMetasploit' ||
    phase === 'savingPoc' ||
    phase === 'savingMarket'

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
      importProgress.value = normaliseImportProgress(latest)

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
    const source = options.source ?? 'all'
    const strategy: ImportStrategy = options.strategy ?? 'full'
    importing.value = true
    importError.value = null

    try {
      if (isClient) {
        startProgressPolling()
      }

      const response = await $fetch<ImportSummary>('/api/fetchKev', {
        method: 'POST',
        body: { mode, source, strategy }
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
  const totalEntries = computed(() => data.value?.totalEntries ?? 0)
  const totalEntriesWithoutYear = computed(() => data.value?.totalEntriesWithoutYear ?? 0)
  const entryLimit = computed(() => data.value?.entryLimit ?? DEFAULT_ENTRY_LIMIT)
  const updatedAt = computed(() => data.value?.updatedAt ?? '')
  const catalogBounds = computed(() => data.value?.catalogBounds ?? { earliest: null, latest: null })
  const market = computed(() => data.value?.market ?? createDefaultMarketOverview())

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
    totalEntries,
    totalEntriesWithoutYear,
    entryLimit,
    updatedAt,
    catalogBounds,
    market,
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
