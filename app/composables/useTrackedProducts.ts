import {
  computed,
  onMounted,
  onScopeDispose,
  ref,
  unref,
  watch,
  type MaybeRef,
  type WatchStopHandle
} from 'vue'
import { useRequestFetch } from '#app'
import type { KevCountDatum, KevEntrySummary, TrackedProduct } from '~/types'

const PRODUCTS_STORAGE_KEY = 'kev.trackedProducts'
const SESSION_STORAGE_KEY = 'kev.sessionId'
const SHOW_ONLY_STORAGE_KEY = 'kev.showOwnedOnly'

type SeverityKey = NonNullable<KevEntrySummary['cvssSeverity']> | 'Unknown'

const severityDisplayMeta: Record<SeverityKey, { label: string; color: string }> = {
  Critical: { label: 'Critical', color: 'error' },
  High: { label: 'High', color: 'error' },
  Medium: { label: 'Medium', color: 'warning' },
  Low: { label: 'Low', color: 'primary' },
  None: { label: 'None', color: 'success' },
  Unknown: { label: 'Unknown', color: 'neutral' }
}

const severityOrder: SeverityKey[] = ['Critical', 'High', 'Medium', 'Low', 'None', 'Unknown']

const recentWindowDaysDefault = 30
const timelineMonthCount = 6

const percentFormatter = new Intl.NumberFormat('en-US', {
  maximumFractionDigits: 1
})

const baseSeverityRecord = (): Record<SeverityKey, number> => ({
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
  None: 0,
  Unknown: 0
})

const buildMonthKey = (value: Date) =>
  `${value.getFullYear()}-${String(value.getMonth() + 1).padStart(2, '0')}`

const buildRecentMonths = (count: number) => {
  const months: Array<{ key: string; label: string }> = []
  const now = new Date()

  for (let offset = count - 1; offset >= 0; offset -= 1) {
    const current = new Date(now.getFullYear(), now.getMonth() - offset, 1)
    months.push({
      key: buildMonthKey(current),
      label: current.toLocaleDateString('en-US', { month: 'short' })
    })
  }

  return months
}

const parseDate = (value: string | null | undefined) => {
  if (!value) {
    return null
  }

  const timestamp = Date.parse(value)
  if (Number.isNaN(timestamp)) {
    return null
  }

  return new Date(timestamp)
}

export type TrackedProductTrendPoint = { label: string; count: number }

export type TrackedProductSeveritySlice = {
  key: SeverityKey
  label: string
  color: string
  count: number
  percent: number
  percentLabel: string
}

export type TrackedProductInsight = {
  product: TrackedProduct
  totalCount: number
  recentCount: number
  severityBreakdown: TrackedProductSeveritySlice[]
  severityCounts: Record<SeverityKey, number>
  trend: TrackedProductTrendPoint[]
  latestAddedAt: string | null
}

export type TrackedProductSummary = {
  productCount: number
  totalCount: number
  recentCount: number
  severityBreakdown: TrackedProductSeveritySlice[]
  recentWindowLabel: string
  hasData: boolean
}

const dedupeProducts = (items: TrackedProduct[]): TrackedProduct[] => {
  const map = new Map<string, TrackedProduct>()
  for (const item of items) {
    map.set(item.productKey, item)
  }
  return Array.from(map.values())
}

export const useTrackedProducts = () => {
  const requestFetch = useRequestFetch()
  const isClient = typeof window !== 'undefined'

  const trackedProducts = ref<TrackedProduct[]>([])
  const showOwnedOnly = ref(false)
  const sessionId = ref<string | null>(null)
  const isSaving = ref(false)
  const saveError = ref<string | null>(null)
  const isReady = ref(false)
  let saveTimer: ReturnType<typeof setTimeout> | null = null

  const kevEntries = ref<KevEntrySummary[]>([])
  const productCountData = ref<KevCountDatum[]>([])
  const recentWindowDays = ref(recentWindowDaysDefault)

  let stopEntriesWatch: WatchStopHandle | null = null
  let stopCountsWatch: WatchStopHandle | null = null
  let stopWindowWatch: WatchStopHandle | null = null

  const trackedProductSet = computed(
    () => new Set(trackedProducts.value.map(item => item.productKey))
  )

  const persistProducts = (items: TrackedProduct[]) => {
    if (!isClient) {
      return
    }
    try {
      window.localStorage.setItem(PRODUCTS_STORAGE_KEY, JSON.stringify(items))
    } catch {
      // Ignore storage failures to keep UX smooth.
    }
  }

  const persistShowOwnedOnly = (value: boolean) => {
    if (!isClient) {
      return
    }
    try {
      window.localStorage.setItem(SHOW_ONLY_STORAGE_KEY, value ? '1' : '0')
    } catch {
      // Ignore storage failures.
    }
  }

  const loadFromStorage = () => {
    if (!isClient) {
      return
    }

    try {
      const storedProducts = window.localStorage.getItem(PRODUCTS_STORAGE_KEY)
      if (storedProducts) {
        const parsed = JSON.parse(storedProducts) as TrackedProduct[]
        trackedProducts.value = dedupeProducts(parsed)
      }
    } catch {
      trackedProducts.value = []
    }

    try {
      const storedSession = window.localStorage.getItem(SESSION_STORAGE_KEY)
      if (storedSession) {
        sessionId.value = storedSession
      }
    } catch {
      sessionId.value = null
    }

    try {
      const storedShowOnly = window.localStorage.getItem(SHOW_ONLY_STORAGE_KEY)
      if (storedShowOnly === '1') {
        showOwnedOnly.value = true
      }
    } catch {
      showOwnedOnly.value = false
    }
  }

  const ensureSession = async (): Promise<string | null> => {
    if (!isClient) {
      return null
    }

    if (sessionId.value) {
      return sessionId.value
    }

    const response = await requestFetch<{ sessionId: string }>('/api/session', {
      method: 'POST'
    })

    sessionId.value = response.sessionId

    try {
      window.localStorage.setItem(SESSION_STORAGE_KEY, response.sessionId)
    } catch {
      // Ignore storage failures.
    }

    return response.sessionId
  }

  const saveToServer = async () => {
    if (!isClient || !isReady.value) {
      return
    }

    const session = await ensureSession()
    if (!session) {
      return
    }

    isSaving.value = true

    try {
      await requestFetch('/api/user-filters', {
        method: 'POST',
        body: {
          sessionId: session,
          products: trackedProducts.value
        }
      })
      saveError.value = null
    } catch (error) {
      saveError.value = error instanceof Error ? error.message : 'Unable to save filters'
    } finally {
      isSaving.value = false
    }
  }

  const scheduleSave = () => {
    if (!isClient || !isReady.value) {
      return
    }

    if (saveTimer) {
      clearTimeout(saveTimer)
    }

    saveTimer = setTimeout(() => {
      void saveToServer()
    }, 400)
  }

  const addTrackedProduct = (product: TrackedProduct) => {
    trackedProducts.value = dedupeProducts([
      ...trackedProducts.value,
      product
    ])
  }

  const removeTrackedProduct = (productKey: string) => {
    trackedProducts.value = trackedProducts.value.filter(
      item => item.productKey !== productKey
    )
  }

  const clearTrackedProducts = () => {
    trackedProducts.value = []
  }

  const setTrackedProducts = (items: TrackedProduct[]) => {
    trackedProducts.value = dedupeProducts(items)
  }

  const connectKevData = (sources: {
    entries?: MaybeRef<KevEntrySummary[] | undefined>
    productCounts?: MaybeRef<KevCountDatum[] | undefined>
    recentWindowDays?: MaybeRef<number | undefined>
  }) => {
    if (stopEntriesWatch) {
      stopEntriesWatch()
      stopEntriesWatch = null
    }

    if (sources.entries) {
      stopEntriesWatch = watch(
        () => unref(sources.entries!) ?? [],
        value => {
          kevEntries.value = Array.isArray(value) ? value : []
        },
        { immediate: true }
      )
    } else {
      kevEntries.value = []
    }

    if (stopCountsWatch) {
      stopCountsWatch()
      stopCountsWatch = null
    }

    if (sources.productCounts) {
      stopCountsWatch = watch(
        () => unref(sources.productCounts!) ?? [],
        value => {
          productCountData.value = Array.isArray(value) ? value : []
        },
        { immediate: true }
      )
    } else {
      productCountData.value = []
    }

    if (stopWindowWatch) {
      stopWindowWatch()
      stopWindowWatch = null
    }

    if (sources.recentWindowDays) {
      stopWindowWatch = watch(
        () => unref(sources.recentWindowDays!) ?? recentWindowDaysDefault,
        value => {
          if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
            recentWindowDays.value = value
          } else {
            recentWindowDays.value = recentWindowDaysDefault
          }
        },
        { immediate: true }
      )
    } else {
      recentWindowDays.value = recentWindowDaysDefault
    }
  }

  const trackedEntries = computed(() => {
    const entries = kevEntries.value
    const keys = trackedProductSet.value

    if (!entries.length || !keys.size) {
      return []
    }

    return entries.filter(entry => keys.has(entry.productKey))
  })

  const trackedProductInsights = computed<TrackedProductInsight[]>(() => {
    const tracked = trackedProducts.value
    const productKeys = trackedProductSet.value

    if (!tracked.length) {
      return []
    }

    const monthMeta = buildRecentMonths(timelineMonthCount)
    const monthIndexMap = new Map(monthMeta.map((item, index) => [item.key, index]))

    const productData = new Map<
      string,
      {
        severityCounts: Record<SeverityKey, number>
        recentCount: number
        trend: number[]
        latestAddedAt: string | null
      }
    >()

    const recentThreshold = (() => {
      const now = Date.now()
      return now - recentWindowDays.value * 24 * 60 * 60 * 1000
    })()

    for (const entry of kevEntries.value) {
      if (!entry.productKey || !productKeys.has(entry.productKey)) {
        continue
      }

      let data = productData.get(entry.productKey)
      if (!data) {
        data = {
          severityCounts: baseSeverityRecord(),
          recentCount: 0,
          trend: Array.from({ length: monthMeta.length }, () => 0),
          latestAddedAt: null
        }
        productData.set(entry.productKey, data)
      }

      const severityKey = (entry.cvssSeverity ?? 'Unknown') as SeverityKey
      data.severityCounts[severityKey] += 1

      const parsed = parseDate(entry.dateAdded)
      if (parsed) {
        const timestamp = parsed.getTime()
        if (timestamp >= recentThreshold) {
          data.recentCount += 1
        }

        const monthKey = buildMonthKey(parsed)
        const index = monthIndexMap.get(monthKey)
        if (typeof index === 'number') {
          data.trend[index] += 1
        }

        if (!data.latestAddedAt) {
          data.latestAddedAt = entry.dateAdded
        } else {
          const currentLatest = parseDate(data.latestAddedAt)
          if (!currentLatest || timestamp > currentLatest.getTime()) {
            data.latestAddedAt = entry.dateAdded
          }
        }
      }
    }

    const productCountMap = new Map<string, number>()
    for (const item of productCountData.value) {
      if (item.key) {
        productCountMap.set(item.key, item.count)
      }
    }

    return tracked.map(product => {
      const data = productData.get(product.productKey) ?? {
        severityCounts: baseSeverityRecord(),
        recentCount: 0,
        trend: Array.from({ length: monthMeta.length }, () => 0),
        latestAddedAt: null
      }

      const totalFromCounts = productCountMap.get(product.productKey)
      const totalFromEntries = severityOrder.reduce(
        (sum, key) => sum + data.severityCounts[key],
        0
      )

      const totalCount =
        typeof totalFromCounts === 'number' && totalFromCounts >= totalFromEntries
          ? totalFromCounts
          : totalFromEntries

      const severityBreakdown = severityOrder
        .map<TrackedProductSeveritySlice | null>(key => {
          const count = data.severityCounts[key]
          if (!count) {
            return null
          }

          const percent = totalCount ? (count / totalCount) * 100 : 0
          const meta = severityDisplayMeta[key]
          return {
            key,
            label: meta.label,
            color: meta.color,
            count,
            percent,
            percentLabel: percentFormatter.format(percent)
          }
        })
        .filter((item): item is TrackedProductSeveritySlice => Boolean(item))

      const trend: TrackedProductTrendPoint[] = monthMeta.map((item, index) => ({
        label: item.label,
        count: data.trend[index] ?? 0
      }))

      return {
        product,
        totalCount,
        recentCount: data.recentCount,
        severityBreakdown,
        severityCounts: data.severityCounts,
        trend,
        latestAddedAt: data.latestAddedAt
      }
    })
  })

  const trackedProductSummary = computed<TrackedProductSummary>(() => {
    const insights = trackedProductInsights.value

    if (!insights.length) {
      return {
        productCount: trackedProducts.value.length,
        totalCount: 0,
        recentCount: 0,
        severityBreakdown: [],
        recentWindowLabel: `${recentWindowDays.value} days`,
        hasData: false
      }
    }

    let totalCount = 0
    let recentCount = 0
    const aggregateSeverity = baseSeverityRecord()

    for (const insight of insights) {
      totalCount += insight.totalCount
      recentCount += insight.recentCount
      for (const key of severityOrder) {
        aggregateSeverity[key] += insight.severityCounts[key]
      }
    }

    const severityBreakdown = severityOrder
      .map<TrackedProductSeveritySlice | null>(key => {
        const count = aggregateSeverity[key]
        if (!count) {
          return null
        }

        const percent = totalCount ? (count / totalCount) * 100 : 0
        const meta = severityDisplayMeta[key]
        return {
          key,
          label: meta.label,
          color: meta.color,
          count,
          percent,
          percentLabel: percentFormatter.format(percent)
        }
      })
      .filter((item): item is TrackedProductSeveritySlice => Boolean(item))

    return {
      productCount: trackedProducts.value.length,
      totalCount,
      recentCount,
      severityBreakdown,
      recentWindowLabel: `${recentWindowDays.value} days`,
      hasData: totalCount > 0
    }
  })

  if (isClient) {
    watch(
      trackedProducts,
      value => {
        persistProducts(value)
        scheduleSave()
      },
      { deep: true }
    )

    watch(
      showOwnedOnly,
      value => {
        persistShowOwnedOnly(value)
      }
    )
  }

  onMounted(() => {
    loadFromStorage()
    isReady.value = true
    scheduleSave()
  })

  onScopeDispose(() => {
    if (saveTimer) {
      clearTimeout(saveTimer)
    }
    if (stopEntriesWatch) {
      stopEntriesWatch()
    }
    if (stopCountsWatch) {
      stopCountsWatch()
    }
    if (stopWindowWatch) {
      stopWindowWatch()
    }
  })

  return {
    trackedProducts,
    trackedProductSet,
    addTrackedProduct,
    removeTrackedProduct,
    clearTrackedProducts,
    setTrackedProducts,
    showOwnedOnly,
    setShowOwnedOnly: (value: boolean) => {
      showOwnedOnly.value = value
    },
    toggleShowOwnedOnly: () => {
      showOwnedOnly.value = !showOwnedOnly.value
    },
    isSaving,
    saveError,
    isReady,
    sessionId,
    ensureSession,
    saveToServer,
    connectKevData,
    trackedEntries,
    trackedProductInsights,
    trackedProductSummary,
    recentWindowLabel: computed(() => `${recentWindowDays.value} days`)
  }
}
