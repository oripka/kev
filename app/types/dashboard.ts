import type { KevEntrySummary } from "~/types";

export type FilterKey = "domain" | "exploit" | "vulnerability" | "vendor" | "product";

export type FilterState = {
  domain: string | null;
  exploit: string | null;
  vulnerability: string | null;
  vendor: string | null;
  product: string | null;
};

export type ActiveFilterKey =
  | FilterKey
  | "search"
  | "wellKnown"
  | "internet"
  | "ransomware"
  | "yearRange"
  | "source"
  | "cvssRange"
  | "epssRange"
  | "owned";

export type ActiveFilter = {
  key: ActiveFilterKey;
  label: string;
  value: string;
};

export type QuickActionKey = "filters" | "focus" | "my-software" | "trends";

export type SeverityKey = NonNullable<KevEntrySummary["cvssSeverity"]> | "Unknown";

export type SeverityDistributionDatum = {
  key: SeverityKey;
  label: string;
  color: string;
  count: number;
  percent: number;
  percentLabel: string;
};

export type LatestAdditionSummary = {
  entry: KevEntrySummary;
  dateLabel: string;
  vendorProduct: string;
  wellKnown: string | null;
  sources: KevEntrySummary["sources"];
  internetExposed: boolean;
  timestamp: number | null;
  isTracked: boolean;
};

export type SourceBadgeMap = Record<
  KevEntrySummary["sources"][number],
  { label: string; color: string }
>;

export type QuickFilterSummaryMetricKey =
  | "count"
  | "year"
  | "activeFilters"
  | "highSeverityShare"
  | "averageCvss"
  | "ransomwareShare"
  | "internetExposedShare";

export type QuickFilterSummaryConfig = {
  metrics: QuickFilterSummaryMetricKey[];
  showActiveFilterChips: boolean;
  showResetButton: boolean;
};

export type TrendDirection = "up" | "down" | "flat";

export type StatTrend = {
  direction: TrendDirection;
  deltaLabel: string;
};

export type LatestAdditionSortKey = "recent" | "epss" | "cvss";

export type LatestAdditionSortOption = {
  label: string;
  value: LatestAdditionSortKey;
  icon: string;
};
