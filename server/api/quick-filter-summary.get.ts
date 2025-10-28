import {
  defaultQuickFilterSummaryConfig,
  normaliseQuickFilterSummaryConfig,
  QUICK_FILTER_SUMMARY_METADATA_KEY,
} from "~/utils/quickFilterSummaryConfig";
import { getMetadataValue } from "../utils/metadata";

export default defineEventHandler(async () => {
  const raw = await getMetadataValue(QUICK_FILTER_SUMMARY_METADATA_KEY);

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
