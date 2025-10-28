import { createError, readBody } from "h3";
import { z } from "zod";
import type { ClassificationReviewResponse } from "~/types";
import { catalogRowToSummary, type CatalogSummaryRow } from "../utils/catalog";
import { runClassificationReview } from "../utils/classification-review";
import { inArray, tables, useDrizzle } from "../utils/drizzle";

const bodySchema = z.object({
  entryIds: z.array(z.string().min(1)).min(1),
  context: z
    .object({
      matchingResultsLabel: z.string().trim().min(1).optional(),
      activeFilters: z
        .array(
          z.object({
            key: z.string().trim(),
            label: z.string().trim(),
            value: z.string().trim(),
          }),
        )
        .optional(),
    })
    .optional(),
});

const MAX_REQUEST_IDS = 20;

export default defineEventHandler(async (event) => {
  const parsed = bodySchema.safeParse(await readBody(event));

  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: "Invalid request payload",
      data: parsed.error.flatten(),
    });
  }

  const uniqueIds = Array.from(new Set(parsed.data.entryIds)).slice(
    0,
    MAX_REQUEST_IDS,
  );

  if (!uniqueIds.length) {
    const response: ClassificationReviewResponse = {
      status: "error",
      message: "No entry IDs supplied for classification review.",
      code: "empty-selection",
    };
    return response;
  }

  const db = useDrizzle();
  const { catalogEntries } = tables;

  const rows = await db
    .select({
      cve_id: catalogEntries.cveId,
      entry_id: catalogEntries.entryId,
      sources: catalogEntries.sources,
      vendor: catalogEntries.vendor,
      vendor_key: catalogEntries.vendorKey,
      product: catalogEntries.product,
      product_key: catalogEntries.productKey,
      vulnerability_name: catalogEntries.vulnerabilityName,
      description: catalogEntries.description,
      due_date: catalogEntries.dueDate,
      date_added: catalogEntries.dateAdded,
      date_published: catalogEntries.datePublished,
      ransomware_use: catalogEntries.ransomwareUse,
      cvss_score: catalogEntries.cvssScore,
      cvss_severity: catalogEntries.cvssSeverity,
      epss_score: catalogEntries.epssScore,
      aliases: catalogEntries.aliases,
      domain_categories: catalogEntries.domainCategories,
      exploit_layers: catalogEntries.exploitLayers,
      vulnerability_categories: catalogEntries.vulnerabilityCategories,
      internet_exposed: catalogEntries.internetExposed,
    })
    .from(catalogEntries)
    .where(inArray(catalogEntries.entryId, uniqueIds))
    .all();

  const rowMap = new Map<string, CatalogSummaryRow>();
  for (const row of rows) {
    rowMap.set(row.entry_id, row);
  }

  const summaries = uniqueIds
    .map((id) => rowMap.get(id))
    .filter((row): row is CatalogSummaryRow => Boolean(row))
    .map((row) => catalogRowToSummary(row));

  if (!summaries.length) {
    const response: ClassificationReviewResponse = {
      status: "error",
      message: "No catalog entries found for the requested IDs.",
      code: "not-found",
    };
    return response;
  }

  const review = await runClassificationReview(summaries, parsed.data.context);

  if (review.status === "ok") {
    const missingEntryIds = uniqueIds.filter((id) => !rowMap.has(id));
    return missingEntryIds.length
      ? { ...review, missingEntryIds }
      : review;
  }

  return review;
});
