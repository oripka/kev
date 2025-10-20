import {
  defaultQuickFilterSummaryConfig,
  normaliseQuickFilterSummaryConfig,
  QUICK_FILTER_SUMMARY_METADATA_KEY,
} from "~/utils/quickFilterSummaryConfig";
import { getMetadata } from "../utils/sqlite";

export default defineEventHandler(() => {
  const raw = getMetadata(QUICK_FILTER_SUMMARY_METADATA_KEY);

  if (!raw) {
    return defaultQuickFilterSummaryConfig;
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    return normaliseQuickFilterSummaryConfig(parsed);
  } catch {
    return defaultQuickFilterSummaryConfig;
  }
});
