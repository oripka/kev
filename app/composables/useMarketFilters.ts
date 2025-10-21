import { computed, ref, watch, type ComputedRef } from 'vue'
import type { KevCountDatum, MarketCategoryDatum, MarketOverview } from '~/types'

type UseMarketFiltersOptions = {
  currencyFormatter?: Intl.NumberFormat
}

const createDefaultMarketOverview = (): MarketOverview => ({
  priceBounds: { minRewardUsd: null, maxRewardUsd: null },
  filteredPriceBounds: { minRewardUsd: null, maxRewardUsd: null },
  offerCount: 0,
  programCounts: [],
  categoryCounts: []
})

export const useMarketFilters = (options?: UseMarketFiltersOptions) => {
  const market = ref<MarketOverview>(createDefaultMarketOverview())
  const priceRange = ref<[number, number]>([0, 0])
  const priceRangeInitialised = ref(false)
  const pendingPriceRange = ref<[number, number] | null>(null)

  const marketPriceBounds = computed(() => market.value.priceBounds)

  const priceSliderReady = computed(
    () =>
      typeof marketPriceBounds.value.minRewardUsd === 'number' &&
      typeof marketPriceBounds.value.maxRewardUsd === 'number' &&
      marketPriceBounds.value.maxRewardUsd > marketPriceBounds.value.minRewardUsd
  )

  const defaultPriceRange = computed<[number, number]>(() => {
    const bounds = marketPriceBounds.value

    if (
      typeof bounds.minRewardUsd === 'number' &&
      typeof bounds.maxRewardUsd === 'number' &&
      Number.isFinite(bounds.minRewardUsd) &&
      Number.isFinite(bounds.maxRewardUsd)
    ) {
      const min = Math.floor(bounds.minRewardUsd)
      const max = Math.ceil(bounds.maxRewardUsd)

      if (Number.isFinite(min) && Number.isFinite(max)) {
        return [min, max]
      }
    }

    return [0, 0]
  })

  watch(
    defaultPriceRange,
    next => {
      if (!priceSliderReady.value) {
        return
      }

      if (!priceRangeInitialised.value) {
        priceRange.value = [next[0], next[1]]
        priceRangeInitialised.value = true
        pendingPriceRange.value = null
        return
      }

      const [currentMin, currentMax] = priceRange.value
      let nextMin = currentMin
      let nextMax = currentMax

      if (currentMin < next[0]) {
        nextMin = next[0]
      }

      if (currentMax > next[1]) {
        nextMax = next[1]
      }

      if (nextMin > nextMax) {
        nextMin = next[0]
        nextMax = next[1]
      }

      if (nextMin !== currentMin || nextMax !== currentMax) {
        priceRange.value = [nextMin, nextMax]
      }
    },
    { immediate: true }
  )

  watch(priceSliderReady, ready => {
    if (ready) {
      const target = pendingPriceRange.value ?? defaultPriceRange.value
      priceRange.value = [target[0], target[1]]
      priceRangeInitialised.value = true
      pendingPriceRange.value = null
    }
  })

  const applyPriceRange = (range: [number, number]) => {
    if (priceSliderReady.value) {
      priceRange.value = [range[0], range[1]]
      priceRangeInitialised.value = true
      pendingPriceRange.value = null
    } else {
      pendingPriceRange.value = [range[0], range[1]]
      priceRangeInitialised.value = false
    }
  }

  const resetPriceRange = () => {
    if (priceSliderReady.value) {
      const [min, max] = defaultPriceRange.value
      priceRange.value = [min, max]
      priceRangeInitialised.value = true
      pendingPriceRange.value = null
    } else {
      priceRange.value = [0, 0]
      priceRangeInitialised.value = false
      pendingPriceRange.value = null
    }
  }

  const normalisePriceRange = (minimum: number | null, maximum: number | null): [number, number] => {
    const [defaultMin, defaultMax] = defaultPriceRange.value

    let start =
      typeof minimum === 'number' && Number.isFinite(minimum)
        ? minimum
        : defaultMin
    let end =
      typeof maximum === 'number' && Number.isFinite(maximum)
        ? maximum
        : defaultMax

    const clampToDefaults = (value: number) => {
      const [minDefault, maxDefault] = defaultPriceRange.value
      return Math.min(Math.max(value, minDefault), maxDefault)
    }

    start = clampToDefaults(start)
    end = clampToDefaults(end)

    if (start > end) {
      ;[start, end] = [end, start]
    }

    return [start, end]
  }

  const applyPriceRangeFromQuery = (minimum: number | null, maximum: number | null) => {
    const nextRange = normalisePriceRange(minimum, maximum)
    applyPriceRange(nextRange)
    return nextRange
  }

  const attachMarketOverview = (source: ComputedRef<MarketOverview>) => {
    watch(
      source,
      next => {
        market.value = next
      },
      { immediate: true }
    )
  }

  const filteredMarketPriceBounds = computed(() => market.value.filteredPriceBounds)

  const filteredMarketPriceSummary = computed(() => {
    const bounds = filteredMarketPriceBounds.value

    if (
      typeof bounds.minRewardUsd === 'number' &&
      typeof bounds.maxRewardUsd === 'number' &&
      Number.isFinite(bounds.minRewardUsd) &&
      Number.isFinite(bounds.maxRewardUsd)
    ) {
      const formatter = options?.currencyFormatter

      if (formatter) {
        return `${formatter.format(bounds.minRewardUsd)} – ${formatter.format(bounds.maxRewardUsd)}`
      }

      return `${bounds.minRewardUsd} – ${bounds.maxRewardUsd}`
    }

    return 'No valuation data in current view.'
  })

  const marketOfferCount = computed<number>(() => market.value.offerCount ?? 0)
  const marketProgramCounts = computed<KevCountDatum[]>(() => market.value.programCounts ?? [])
  const marketCategoryCounts = computed<MarketCategoryDatum[]>(() => market.value.categoryCounts ?? [])

  return {
    attachMarketOverview,
    priceRange,
    priceSliderReady,
    defaultPriceRange,
    applyPriceRange,
    resetPriceRange,
    applyPriceRangeFromQuery,
    normalisePriceRange,
    filteredMarketPriceSummary,
    marketOfferCount,
    marketProgramCounts,
    marketCategoryCounts
  }
}
