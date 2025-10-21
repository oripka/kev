import { computed } from "vue";
import type { ComputedRef } from "vue";
import type { MarketOverview } from "~/types";

export const useMarketMetrics = (
  marketOverview: ComputedRef<MarketOverview>,
) => {
  const currencyFormatter = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  });

  const marketPriceBounds = computed(() => marketOverview.value.priceBounds);

  const defaultPriceRange = computed<[number, number]>(() => {
    const bounds = marketPriceBounds.value;

    if (
      typeof bounds.minRewardUsd === "number" &&
      typeof bounds.maxRewardUsd === "number" &&
      Number.isFinite(bounds.minRewardUsd) &&
      Number.isFinite(bounds.maxRewardUsd)
    ) {
      const min = Math.floor(bounds.minRewardUsd);
      const max = Math.ceil(bounds.maxRewardUsd);

      if (Number.isFinite(min) && Number.isFinite(max)) {
        return [min, max];
      }
    }

    return [0, 0];
  });

  const marketOfferCount = computed(() => marketOverview.value.offerCount ?? 0);
  const marketProgramCounts = computed(
    () => marketOverview.value.programCounts ?? [],
  );
  const marketCategoryCounts = computed(
    () => marketOverview.value.categoryCounts ?? [],
  );

  const filteredMarketPriceBounds = computed(
    () => marketOverview.value.filteredPriceBounds,
  );

  const filteredMarketPriceSummary = computed(() => {
    const bounds = filteredMarketPriceBounds.value;

    if (
      typeof bounds.minRewardUsd === "number" &&
      typeof bounds.maxRewardUsd === "number" &&
      Number.isFinite(bounds.minRewardUsd) &&
      Number.isFinite(bounds.maxRewardUsd)
    ) {
      return `${currencyFormatter.format(bounds.minRewardUsd)} – ${currencyFormatter.format(bounds.maxRewardUsd)}`;
    }

    return "No valuation data in current view.";
  });

  return {
    currencyFormatter,
    defaultPriceRange,
    filteredMarketPriceBounds,
    filteredMarketPriceSummary,
    marketCategoryCounts,
    marketOfferCount,
    marketPriceBounds,
    marketProgramCounts,
  };
};
