import type {
  QuickFilterSummaryConfig,
  QuickFilterSummaryMetricKey,
} from "~/types/dashboard";

export const QUICK_FILTER_SUMMARY_METADATA_KEY = "quick-filter-summary-config";

export const quickFilterSummaryMetricOrder = [
  "count",
  "year",
  "activeFilters",
  "highSeverityShare",
  "averageCvss",
  "ransomwareShare",
  "internetExposedShare",
] as const satisfies readonly QuickFilterSummaryMetricKey[];

type MetricInfo = {
  label: string;
  description: string;
  icon: string;
};

export const quickFilterSummaryMetricInfo: Record<QuickFilterSummaryMetricKey, MetricInfo> = {
  count: {
    label: "In view",
    description: "Number of catalog entries that match the current filters.",
    icon: "i-lucide-list-checks",
  },
  year: {
    label: "Year",
    description: "Active year or range applied to the dashboard results.",
    icon: "i-lucide-calendar",
  },
  activeFilters: {
    label: "Filters",
    description: "How many quick filters are currently applied.",
    icon: "i-lucide-filter",
  },
  highSeverityShare: {
    label: "High/Critical",
    description: "Share of filtered entries with High or Critical CVSS severity.",
    icon: "i-lucide-activity",
  },
  averageCvss: {
    label: "Avg CVSS",
    description: "Average CVSS score for matching entries with scoring data.",
    icon: "i-lucide-gauge",
  },
  ransomwareShare: {
    label: "Ransomware",
    description: "Share of matching entries linked to ransomware activity.",
    icon: "i-lucide-flame",
  },
  internetExposedShare: {
    label: "Internet exposed",
    description: "Share of matching entries likely exposed to the internet.",
    icon: "i-lucide-radar",
  },
};

export const defaultQuickFilterSummaryConfig: QuickFilterSummaryConfig = {
  metrics: ["count", "year"],
  showActiveFilterChips: true,
  showResetButton: true,
};

const metricKeySet = new Set<QuickFilterSummaryMetricKey>(quickFilterSummaryMetricOrder);

export const isQuickFilterSummaryMetricKey = (
  value: unknown,
): value is QuickFilterSummaryMetricKey =>
  typeof value === "string" && metricKeySet.has(value as QuickFilterSummaryMetricKey);

const cloneMetrics = (metrics: QuickFilterSummaryMetricKey[]): QuickFilterSummaryMetricKey[] => [
  ...metrics,
];

export const cloneQuickFilterSummaryConfig = (
  config: QuickFilterSummaryConfig,
): QuickFilterSummaryConfig => ({
  metrics: cloneMetrics(config.metrics),
  showActiveFilterChips: config.showActiveFilterChips,
  showResetButton: config.showResetButton,
});

export const normaliseQuickFilterSummaryConfig = (
  value: Partial<QuickFilterSummaryConfig> | null | undefined,
): QuickFilterSummaryConfig => {
  if (!value || typeof value !== "object") {
    return cloneQuickFilterSummaryConfig(defaultQuickFilterSummaryConfig);
  }

  const rawMetrics = Array.isArray(value.metrics)
    ? value.metrics.filter(isQuickFilterSummaryMetricKey)
    : [];

  const uniqueMetrics = new Set<QuickFilterSummaryMetricKey>(rawMetrics);
  const orderedMetrics = quickFilterSummaryMetricOrder.filter((key) => uniqueMetrics.has(key));

  const metrics = orderedMetrics.length
    ? orderedMetrics
    : cloneMetrics(defaultQuickFilterSummaryConfig.metrics);

  const showActiveFilterChips =
    typeof value.showActiveFilterChips === "boolean"
      ? value.showActiveFilterChips
      : defaultQuickFilterSummaryConfig.showActiveFilterChips;

  const showResetButton =
    typeof value.showResetButton === "boolean"
      ? value.showResetButton
      : defaultQuickFilterSummaryConfig.showResetButton;

  return {
    metrics,
    showActiveFilterChips,
    showResetButton,
  };
};

export const areQuickFilterSummaryConfigsEqual = (
  a: QuickFilterSummaryConfig,
  b: QuickFilterSummaryConfig,
) =>
  a.showActiveFilterChips === b.showActiveFilterChips &&
  a.showResetButton === b.showResetButton &&
  a.metrics.length === b.metrics.length &&
  a.metrics.every((key, index) => key === b.metrics[index]);
