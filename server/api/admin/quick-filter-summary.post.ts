import { createError, readBody } from "h3";
import { z } from "zod";
import {
  cloneQuickFilterSummaryConfig,
  normaliseQuickFilterSummaryConfig,
  QUICK_FILTER_SUMMARY_METADATA_KEY,
  quickFilterSummaryMetricOrder,
} from "~/utils/quickFilterSummaryConfig";
import type {
  QuickFilterSummaryConfig,
  QuickFilterSummaryMetricKey,
} from "~/types/dashboard";
import { setMetadata } from "../../utils/sqlite";

const metricSchema = z.enum(
  quickFilterSummaryMetricOrder as [
    QuickFilterSummaryMetricKey,
    ...QuickFilterSummaryMetricKey[],
  ],
);

const bodySchema = z
  .object({
    metrics: z.array(metricSchema).optional(),
    showActiveFilterChips: z.boolean().optional(),
    showResetButton: z.boolean().optional(),
  })
  .strict();

export default defineEventHandler(async (event) => {
  const parsed = bodySchema.safeParse(await readBody(event));

  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: "Invalid request payload",
      data: parsed.error.flatten(),
    });
  }

  const config: QuickFilterSummaryConfig = normaliseQuickFilterSummaryConfig(parsed.data);

  setMetadata(QUICK_FILTER_SUMMARY_METADATA_KEY, JSON.stringify(config));

  return cloneQuickFilterSummaryConfig(config);
});
