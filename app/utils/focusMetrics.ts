import { differenceInCalendarDays, parseISO, subMonths, subYears } from "date-fns";
import type { KevEntrySummary, KevTimeline } from "~/types";

export type FocusMetricKey =
  | "totalMatches"
  | "fiveYearMatchCount"
  | "rolling12MonthCount"
  | "publicExploitShare"
  | "pocWithin30DaysShare"
  | "dueDateCoverageShare"
  | "internetExposedShare"
  | "internetExposedCount"
  | "ransomwareShare"
  | "highSeverityShare"
  | "medianExploitWindowDays"
  | "medianPatchWindowDays";

export type FocusMetricResult = {
  value: string;
  caption?: string;
  hint?: string;
};

export type FocusMetricContext = {
  entries: KevEntrySummary[];
  timeline: KevTimeline;
  totalEntries: number;
};

const numberFormatter = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });
const percentFormatter = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });
const precisePercentFormatter = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });

const parseDate = (value: string | null): Date | null => {
  if (!value) {
    return null;
  }

  const parsed = parseISO(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed;
  }

  const fallback = new Date(value);
  return Number.isNaN(fallback.getTime()) ? null : fallback;
};

const computeMedian = (values: number[]): number | null => {
  if (!values.length) {
    return null;
  }

  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }

  return sorted[mid];
};

const formatDays = (value: number | null): string => {
  if (value === null || Number.isNaN(value)) {
    return "—";
  }

  if (value < 1) {
    return "<1 day";
  }

  return `${Math.round(value)} days`;
};

const formatPercent = (share: number | null, precision: "coarse" | "fine" = "coarse"): string => {
  if (share === null || Number.isNaN(share)) {
    return "—";
  }

  const formatter = precision === "fine" ? precisePercentFormatter : percentFormatter;
  return `${formatter.format(share * 100)}%`;
};

const computeShare = (count: number, total: number): number | null => {
  if (!total) {
    return null;
  }

  return count / total;
};

const countWithinMonths = (timeline: KevTimeline, months: number): number => {
  const cutoff = subMonths(new Date(), months);
  const buckets = timeline.buckets?.monthly ?? [];

  if (!buckets.length) {
    return 0;
  }

  let total = 0;

  for (const bucket of buckets) {
    const parsed = parseDate(bucket.date);
    if (!parsed) {
      continue;
    }

    if (parsed >= cutoff) {
      total += bucket.count;
    }
  }

  return total;
};

export const computeFocusMetric = (
  key: FocusMetricKey,
  context: FocusMetricContext,
): FocusMetricResult => {
  const { entries, timeline, totalEntries } = context;
  const entryCount = entries.length;

  switch (key) {
    case "totalMatches": {
      return {
        value: numberFormatter.format(totalEntries || entryCount),
        caption: "CVE entries mapped to this focus",
      };
    }

    case "fiveYearMatchCount": {
      const threshold = subYears(new Date(), 5);
      const count = entries.filter((entry) => {
        const date = parseDate(entry.dateAdded) ?? parseDate(entry.datePublished);
        if (!date) {
          return false;
        }
        return date >= threshold;
      }).length;

      return {
        value: numberFormatter.format(count),
        caption: "Observed in the last five years",
      };
    }

    case "rolling12MonthCount": {
      const count = countWithinMonths(timeline, 12);
      if (!count && entryCount) {
        const cutoff = subMonths(new Date(), 12);
        for (const entry of entries) {
          const date = parseDate(entry.dateAdded);
          if (date && date >= cutoff) {
            return {
              value: numberFormatter.format(
                entries.filter((item) => {
                  const added = parseDate(item.dateAdded);
                  return added && added >= cutoff;
                }).length,
              ),
              caption: "Rolling 12-month total (entry-based)",
            };
          }
        }
      }

      return {
        value: numberFormatter.format(count),
        caption: "Rolling 12-month total",
      };
    }

    case "publicExploitShare": {
      const count = entries.filter((entry) =>
        entry.sources.some((source) => source === "metasploit" || source === "poc"),
      ).length;

      const share = computeShare(count, entryCount);
      return {
        value: formatPercent(share),
        caption: `${count} with public tooling`,
      };
    }

    case "pocWithin30DaysShare": {
      if (!entryCount) {
        return { value: "—", caption: "No data" };
      }

      const threshold = 30;
      let withData = 0;
      let fastTracks = 0;

      for (const entry of entries) {
        const published = parseDate(entry.datePublished);
        if (!published) {
          continue;
        }

        const exploitDate =
          parseDate(entry.pocPublishedAt) ?? parseDate(entry.dateAdded);

        if (!exploitDate) {
          continue;
        }

        withData += 1;
        const delta = differenceInCalendarDays(exploitDate, published);
        if (delta >= 0 && delta <= threshold) {
          fastTracks += 1;
        }
      }

      const denominator = withData || entryCount;
      const share = computeShare(fastTracks, denominator);

      return {
        value: formatPercent(share, "fine"),
        caption: `${fastTracks} observed ≤${threshold} days after disclosure`,
      };
    }

    case "dueDateCoverageShare": {
      const count = entries.filter((entry) => typeof entry.dueDate === "string" && entry.dueDate.trim().length > 0).length;
      const share = computeShare(count, entryCount);
      return {
        value: formatPercent(share),
        caption: `${count} entries with remediation guidance`,
      };
    }

    case "internetExposedShare": {
      const count = entries.filter((entry) => entry.internetExposed).length;
      const share = computeShare(count, entryCount);
      return {
        value: formatPercent(share),
        caption: `${count} flagged as internet exposed`,
      };
    }

    case "internetExposedCount": {
      const count = entries.filter((entry) => entry.internetExposed).length;
      return {
        value: numberFormatter.format(count),
        caption: "Internet-exposed entries",
      };
    }

    case "ransomwareShare": {
      const count = entries.filter((entry) =>
        (entry.ransomwareUse ?? "").toLowerCase().includes("known"),
      ).length;
      const share = computeShare(count, entryCount);
      return {
        value: formatPercent(share),
        caption: `${count} linked to ransomware activity`,
      };
    }

    case "highSeverityShare": {
      const count = entries.filter((entry) => {
        const severity = entry.cvssSeverity;
        return severity === "High" || severity === "Critical";
      }).length;
      const share = computeShare(count, entryCount);
      return {
        value: formatPercent(share),
        caption: `${count} rated High or Critical`,
      };
    }

    case "medianExploitWindowDays": {
      const values: number[] = [];
      for (const entry of entries) {
        const published = parseDate(entry.datePublished);
        const observed = parseDate(entry.dateAdded) ?? parseDate(entry.pocPublishedAt);
        if (!published || !observed) {
          continue;
        }

        const delta = differenceInCalendarDays(observed, published);
        if (delta >= 0) {
          values.push(delta);
        }
      }

      const median = computeMedian(values);
      return {
        value: formatDays(median),
        caption: "Median time from disclosure to KEV listing",
      };
    }

    case "medianPatchWindowDays": {
      const values: number[] = [];
      for (const entry of entries) {
        const added = parseDate(entry.dateAdded);
        const due = parseDate(entry.dueDate);
        if (!added || !due) {
          continue;
        }

        const delta = differenceInCalendarDays(due, added);
        if (Number.isFinite(delta) && delta >= 0) {
          values.push(delta);
        }
      }

      const median = computeMedian(values);
      return {
        value: formatDays(median),
        caption: "Median window between KEV listing and remediation due date",
      };
    }

    default:
      return { value: "—" };
  }
};
