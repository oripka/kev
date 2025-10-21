import { useRuntimeConfig } from "#imports";
import { curatedProductTaxonomy } from "~/utils/classification";
import type {
  CatalogSource,
  ClassificationReviewCategorySet,
  ClassificationReviewHeuristicIdea,
  ClassificationReviewIssue,
  ClassificationReviewOverview,
  ClassificationReviewRequestContext,
  ClassificationReviewResponse,
  ClassificationReviewSuccess,
  ClassificationReviewTaxonomySuggestion,
  KevDomainCategory,
  KevEntrySummary,
  KevExploitLayer,
  KevVulnerabilityCategory,
} from "~/types";

const DEFAULT_MAX_ENTRIES = 12;
const DEFAULT_MODEL = "gpt-5-mini-nano";
const DEFAULT_API_URL = "https://api.openai.com/v1/chat/completions";
const DEFAULT_TEMPERATURE = 0.2;

type RuntimeConfig = {
  llmAudit?: {
    apiUrl: string;
    apiKey: string;
    orgId: string;
    model: string;
    maxEntries: string;
    temperature?: string;
  };
  openai?: {
    apiKey: string;
  };
};

type ClassificationRuntimeConfig = {
  apiUrl: string;
  apiKey: string;
  organisationId?: string;
  model: string;
  maxEntries: number;
  temperature: number | null;
};

const parseTemperature = (value: string | undefined): number | null => {
  if (!value) {
    return null;
  }

  const parsed = Number.parseFloat(value);

  return Number.isFinite(parsed) ? parsed : null;
};

const resolveClassificationRuntimeConfig = (): ClassificationRuntimeConfig => {
  const config = useRuntimeConfig<RuntimeConfig>();
  const llmAudit = config.llmAudit ?? {
    apiUrl: "",
    apiKey: "",
    orgId: "",
    model: "",
    maxEntries: "",
    temperature: "",
  };

  const parsedMaxEntries = Number.parseInt(llmAudit.maxEntries || "", 10);
  const apiUrl = llmAudit.apiUrl || DEFAULT_API_URL;
  const parsedTemperature = parseTemperature(llmAudit.temperature);
  const fallbackTemperature =
    apiUrl === DEFAULT_API_URL ? DEFAULT_TEMPERATURE : null;

  return {
    apiUrl,
    apiKey: llmAudit.apiKey || config.openai?.apiKey || "",
    organisationId: llmAudit.orgId || undefined,
    model: llmAudit.model || DEFAULT_MODEL,
    maxEntries:
      Number.isFinite(parsedMaxEntries) && parsedMaxEntries > 0
        ? Math.max(1, parsedMaxEntries)
        : DEFAULT_MAX_ENTRIES,
    temperature: parsedTemperature ?? fallbackTemperature,
  };
};

const CLASSIFICATION_HEURISTICS_OVERVIEW = `
- Domain classification normalises vendor and product names, applies curated overrides, and analyses vulnerability text for web, networking, mail, ICS, and operating-system signals. CVSS network vectors plus remote execution context influence the Internet Edge flag.
- Curated hints can fully replace or extend domain categories and toggle the internetExposed flag. They also express serverBias or clientBias hints consumed by exploit heuristics.
- Exploit layers examine description text, CVSS AV/PR/UI values, and curated hints to split remote code execution into server- vs. client-side buckets, identify DoS, auth bypass, privilege escalation, and configuration abuse scenarios.
- Vulnerability categories rely on pattern families for memory corruption, injection, traversal, SSRF, logic flaws, etc. Remote execution context without a better match defaults to Remote Code Execution, otherwise Other.
- Helper heuristics distinguish Cisco IOS vs. Apple iOS, suppress conflicting web/non-web labels, and only keep the Other category when it is the sole match.`.trim();

type SanitisedHint = {
  vendorKey: string | null;
  productKey: string;
  categories?: KevDomainCategory[];
  addCategories?: KevDomainCategory[];
  internetExposed?: boolean | null;
  serverBias?: boolean | null;
  clientBias?: boolean | null;
};

type AuditEntry = {
  id: string;
  cveId: string;
  vendor: string;
  vendorKey: string;
  product: string;
  productKey: string;
  vulnerabilityName: string;
  description: string;
  domainCategories: KevDomainCategory[];
  exploitLayers: KevExploitLayer[];
  vulnerabilityCategories: KevVulnerabilityCategory[];
  internetExposed: boolean;
  sources: CatalogSource[];
  cvssScore: number | null;
  epssScore: number | null;
  curatedHints: SanitisedHint[];
};

type ChatCompletionResponse = {
  model?: string;
  choices?: Array<{
    message?: { content?: string };
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
};

const vendorProductHintMap = new Map<string, SanitisedHint[]>();
const productHintMap = new Map<string, SanitisedHint[]>();

const cloneHint = (hint: SanitisedHint): SanitisedHint => ({
  vendorKey: hint.vendorKey,
  productKey: hint.productKey,
  categories: hint.categories ? [...hint.categories] : undefined,
  addCategories: hint.addCategories ? [...hint.addCategories] : undefined,
  internetExposed: hint.internetExposed ?? null,
  serverBias: hint.serverBias ?? null,
  clientBias: hint.clientBias ?? null,
});

for (const entry of curatedProductTaxonomy) {
  const sanitised: SanitisedHint = {
    vendorKey: entry.vendorKey ?? null,
    productKey: entry.productKey,
    categories: entry.categories ? [...entry.categories] : undefined,
    addCategories: entry.addCategories ? [...entry.addCategories] : undefined,
    internetExposed:
      entry.internetExposed === undefined ? null : entry.internetExposed,
    serverBias: entry.serverBias === undefined ? null : entry.serverBias,
    clientBias: entry.clientBias === undefined ? null : entry.clientBias,
  };

  if (entry.vendorKey) {
    const key = `${entry.vendorKey}::${entry.productKey}`;
    const existing = vendorProductHintMap.get(key) ?? [];
    existing.push(sanitised);
    vendorProductHintMap.set(key, existing);
  } else {
    const existing = productHintMap.get(entry.productKey) ?? [];
    existing.push(sanitised);
    productHintMap.set(entry.productKey, existing);
  }
}

const getCuratedHints = (
  vendorKey: string,
  productKey: string,
): SanitisedHint[] => {
  const hints: SanitisedHint[] = [];
  const normalisedProduct = productKey.trim();
  const normalisedVendor = vendorKey.trim();

  if (normalisedVendor) {
    const vendorHints = vendorProductHintMap.get(
      `${normalisedVendor}::${normalisedProduct}`,
    );
    if (vendorHints) {
      for (const hint of vendorHints) {
        hints.push(cloneHint(hint));
      }
    }
  }

  const productHints = productHintMap.get(normalisedProduct);
  if (productHints) {
    for (const hint of productHints) {
      hints.push(cloneHint(hint));
    }
  }

  return hints;
};

const sanitiseDescription = (
  value: string | null | undefined,
  limit = 600,
): string => {
  if (!value) {
    return "";
  }

  const normalised = value.replace(/\s+/g, " ").trim();
  if (!normalised) {
    return "";
  }

  if (normalised.length <= limit) {
    return normalised;
  }

  return `${normalised.slice(0, limit - 1).trim()}…`;
};

const toAuditEntry = (entry: KevEntrySummary): AuditEntry => ({
  id: entry.id,
  cveId: entry.cveId,
  vendor: entry.vendor,
  vendorKey: entry.vendorKey,
  product: entry.product,
  productKey: entry.productKey,
  vulnerabilityName: entry.vulnerabilityName,
  description: sanitiseDescription(entry.description, 700),
  domainCategories: [...entry.domainCategories],
  exploitLayers: [...entry.exploitLayers],
  vulnerabilityCategories: [...entry.vulnerabilityCategories],
  internetExposed: Boolean(entry.internetExposed),
  sources: [...entry.sources],
  cvssScore:
    typeof entry.cvssScore === "number" && Number.isFinite(entry.cvssScore)
      ? entry.cvssScore
      : null,
  epssScore:
    typeof entry.epssScore === "number" && Number.isFinite(entry.epssScore)
      ? entry.epssScore
      : null,
  curatedHints: getCuratedHints(entry.vendorKey ?? "", entry.productKey ?? ""),
});

const toCategoryCounts = <Key extends keyof Pick<AuditEntry, "domainCategories" | "exploitLayers" | "vulnerabilityCategories">>(
  entries: AuditEntry[],
  key: Key,
) => {
  const counts = new Map<string, number>();

  for (const entry of entries) {
    const values = entry[key] as AuditEntry[Key];
    for (const value of values as string[]) {
      counts.set(value, (counts.get(value) ?? 0) + 1);
    }
  }

  const total = entries.length || 1;

  return Array.from(counts.entries())
    .sort((first, second) => second[1] - first[1])
    .map(([value, count]) => ({
      value,
      count,
      share: count / total,
    }));
};

const buildOverview = (entries: AuditEntry[]): ClassificationReviewOverview => ({
  totalEntries: entries.length,
  domainCounts: toCategoryCounts(entries, "domainCategories") as Array<{
    value: KevDomainCategory;
    count: number;
    share: number;
  }>,
  exploitCounts: toCategoryCounts(entries, "exploitLayers") as Array<{
    value: KevExploitLayer;
    count: number;
    share: number;
  }>,
  vulnerabilityCounts: toCategoryCounts(
    entries,
    "vulnerabilityCategories",
  ) as Array<{ value: KevVulnerabilityCategory; count: number; share: number }>,
  internetExposure: {
    exposed: entries.filter((entry) => entry.internetExposed).length,
    total: entries.length,
  },
  sources: Array.from(
    new Set(entries.flatMap((entry) => entry.sources ?? [])),
  ).sort(),
});

const safeString = (value: unknown, limit = 800): string => {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return "";
    }
    return trimmed.length <= limit
      ? trimmed
      : `${trimmed.slice(0, Math.max(0, limit - 1)).trim()}…`;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return "";
};

const toStringList = (value: unknown, limit = 10, itemLimit = 400): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }

  const result: string[] = [];

  for (const item of value) {
    if (typeof item !== "string") {
      continue;
    }
    const trimmed = item.trim();
    if (!trimmed) {
      continue;
    }
    result.push(
      trimmed.length <= itemLimit
        ? trimmed
        : `${trimmed.slice(0, Math.max(0, itemLimit - 1)).trim()}…`,
    );
    if (result.length >= limit) {
      break;
    }
  }

  return result;
};

const toCategoryArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const items = value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
  return items.length ? items : undefined;
};

const parseCategorySet = (
  value: unknown,
): ClassificationReviewCategorySet | null => {
  if (!value || typeof value !== "object") {
    return null;
  }

  const domain = toCategoryArray((value as { domain?: unknown }).domain);
  const exploit = toCategoryArray((value as { exploit?: unknown }).exploit);
  const vulnerability = toCategoryArray(
    (value as { vulnerability?: unknown }).vulnerability,
  );
  const internetExposedRaw = (value as { internetExposed?: unknown })
    .internetExposed;

  const hasData =
    (domain && domain.length) ||
    (exploit && exploit.length) ||
    (vulnerability && vulnerability.length) ||
    typeof internetExposedRaw === "boolean";

  if (!hasData) {
    return null;
  }

  const result: ClassificationReviewCategorySet = {};

  if (domain && domain.length) {
    result.domain = domain as KevDomainCategory[];
  }

  if (exploit && exploit.length) {
    result.exploit = exploit as KevExploitLayer[];
  }

  if (vulnerability && vulnerability.length) {
    result.vulnerability = vulnerability as KevVulnerabilityCategory[];
  }

  if (typeof internetExposedRaw === "boolean") {
    result.internetExposed = internetExposedRaw;
  }

  return Object.keys(result).length ? result : null;
};

const parseConfidence = (
  value: unknown,
): "low" | "medium" | "high" => {
  if (!value) {
    return "medium";
  }

  const label = String(value).trim().toLowerCase();
  if (label.includes("high")) {
    return "high";
  }
  if (label.includes("low")) {
    return "low";
  }
  return "medium";
};

const parseIssue = (value: unknown): ClassificationReviewIssue | null => {
  if (!value || typeof value !== "object") {
    return null;
  }

  const cveId = safeString((value as { cveId?: unknown }).cveId).toUpperCase();
  const summary = safeString((value as { summary?: unknown }).summary);

  if (!cveId || !summary) {
    return null;
  }

  const suspectedIssues = toStringList(
    (value as { suspectedIssues?: unknown }).suspectedIssues,
    8,
  );
  const recommendedCategories = parseCategorySet(
    (value as { recommendedCategories?: unknown }).recommendedCategories,
  );
  const justification = safeString(
    (value as { justification?: unknown }).justification,
  );
  const confidence = parseConfidence(
    (value as { confidence?: unknown }).confidence,
  );

  return {
    cveId,
    summary,
    suspectedIssues,
    recommendedCategories: recommendedCategories ?? null,
    justification,
    confidence,
  };
};

const parseTaxonomySuggestion = (
  value: unknown,
): ClassificationReviewTaxonomySuggestion | null => {
  if (!value || typeof value !== "object") {
    return null;
  }

  const productKey = safeString(
    (value as { productKey?: unknown }).productKey,
  ).toLowerCase();

  if (!productKey) {
    return null;
  }

  const vendorKeyRaw = safeString(
    (value as { vendorKey?: unknown }).vendorKey,
  ).toLowerCase();
  const proposedCategories = toCategoryArray(
    (value as { proposedCategories?: unknown }).proposedCategories,
  ) as KevDomainCategory[] | undefined;
  const proposedAddCategories = toCategoryArray(
    (value as { proposedAddCategories?: unknown }).proposedAddCategories,
  ) as KevDomainCategory[] | undefined;
  const rationale = safeString((value as { rationale?: unknown }).rationale, 600);
  const internetExposed = (value as { internetExposed?: unknown }).internetExposed;
  const serverBias = (value as { serverBias?: unknown }).serverBias;
  const clientBias = (value as { clientBias?: unknown }).clientBias;

  return {
    vendorKey: vendorKeyRaw || null,
    productKey,
    proposedCategories: proposedCategories ?? [],
    proposedAddCategories: proposedAddCategories ?? [],
    internetExposed:
      typeof internetExposed === "boolean" ? internetExposed : undefined,
    serverBias: typeof serverBias === "boolean" ? serverBias : undefined,
    clientBias: typeof clientBias === "boolean" ? clientBias : undefined,
    rationale,
  };
};

const parseHeuristicImprovement = (
  value: unknown,
): ClassificationReviewHeuristicIdea | null => {
  if (!value || typeof value !== "object") {
    return null;
  }

  const focusArea = safeString((value as { focusArea?: unknown }).focusArea, 160);
  const description = safeString(
    (value as { description?: unknown }).description,
    600,
  );
  const justification = safeString(
    (value as { justification?: unknown }).justification,
    600,
  );

  if (!focusArea || !description) {
    return null;
  }

  return { focusArea, description, justification };
};

const stripJsonFence = (value: string): string => {
  const trimmed = value.trim();
  if (trimmed.startsWith("```")) {
    const newlineIndex = trimmed.indexOf("\n");
    if (newlineIndex !== -1) {
      const fenceLanguage = trimmed
        .slice(3, newlineIndex)
        .trim()
        .toLowerCase();
      if (fenceLanguage === "json") {
        const closingIndex = trimmed.lastIndexOf("```");
        if (closingIndex > newlineIndex) {
          return trimmed.slice(newlineIndex + 1, closingIndex).trim();
        }
      }
    }
  }
  return trimmed;
};

const buildFilterSummary = (
  context?: ClassificationReviewRequestContext,
): string => {
  if (!context) {
    return "No filter context provided.";
  }

  const parts: string[] = [];

  if (context.matchingResultsLabel) {
    parts.push(`Matching results in view: ${context.matchingResultsLabel}.`);
  }

  if (context.activeFilters?.length) {
    const labels = context.activeFilters
      .map((filter) => `${filter.label}: ${filter.value}`)
      .join("; ");
    if (labels) {
      parts.push(`Active filters → ${labels}.`);
    }
  }

  return parts.length ? parts.join(" ") : "No filter context provided.";
};

const systemPrompt = [
  "You are a security analyst auditing how exploited vulnerabilities are automatically categorised.",
  "Check domainCategories, exploitLayers, vulnerabilityCategories, and the internetExposed flag for each entry.",
  "When you spot problems, propose targeted fixes to the heuristics in classification.ts (e.g. add curated hints, adjust pattern groups, tweak CVSS thresholds).",
  "Always respond with JSON only.",
  `Heuristics overview derived from classification.ts:\n${CLASSIFICATION_HEURISTICS_OVERVIEW}`,
].join("\n\n");

const buildUserPrompt = (
  entries: AuditEntry[],
  overview: ClassificationReviewOverview,
  context?: ClassificationReviewRequestContext,
): string => {
  const payload = {
    context: buildFilterSummary(context),
    sample: entries,
    overview,
  };

  return [
    "Audit the following dataset excerpt and flag misclassifications.",
    "Focus on potential category mismatches, missing Internet Edge signals, and opportunities to strengthen heuristics.",
    "Return JSON with keys: issues, taxonomySuggestions, heuristicImprovements, generalRecommendations.",
    "Dataset JSON:",
    "```json",
    JSON.stringify(payload, null, 2),
    "```",
  ].join("\n");
};

const normaliseSuccess = (
  data: unknown,
): {
  issues: ClassificationReviewIssue[];
  taxonomySuggestions: ClassificationReviewTaxonomySuggestion[];
  heuristicImprovements: ClassificationReviewHeuristicIdea[];
  generalRecommendations: string[];
} => {
  if (!data || typeof data !== "object") {
    return {
      issues: [],
      taxonomySuggestions: [],
      heuristicImprovements: [],
      generalRecommendations: [],
    };
  }

  const issuesRaw = (data as { issues?: unknown }).issues;
  const taxonomyRaw = (data as { taxonomySuggestions?: unknown })
    .taxonomySuggestions;
  const heuristicsRaw = (data as { heuristicImprovements?: unknown })
    .heuristicImprovements;
  const recommendationsRaw = (data as { generalRecommendations?: unknown })
    .generalRecommendations;

  const issues: ClassificationReviewIssue[] = [];
  if (Array.isArray(issuesRaw)) {
    for (const item of issuesRaw) {
      const issue = parseIssue(item);
      if (issue) {
        issues.push(issue);
      }
      if (issues.length >= 15) {
        break;
      }
    }
  }

  const taxonomySuggestions: ClassificationReviewTaxonomySuggestion[] = [];
  if (Array.isArray(taxonomyRaw)) {
    for (const item of taxonomyRaw) {
      const suggestion = parseTaxonomySuggestion(item);
      if (suggestion) {
        taxonomySuggestions.push(suggestion);
      }
      if (taxonomySuggestions.length >= 10) {
        break;
      }
    }
  }

  const heuristicImprovements: ClassificationReviewHeuristicIdea[] = [];
  if (Array.isArray(heuristicsRaw)) {
    for (const item of heuristicsRaw) {
      const improvement = parseHeuristicImprovement(item);
      if (improvement) {
        heuristicImprovements.push(improvement);
      }
      if (heuristicImprovements.length >= 10) {
        break;
      }
    }
  }

  const generalRecommendations = toStringList(recommendationsRaw, 10, 500);

  return { issues, taxonomySuggestions, heuristicImprovements, generalRecommendations };
};

const buildUsage = (
  usage: ChatCompletionResponse["usage"],
): ClassificationReviewSuccess["usage"] => {
  if (!usage) {
    return undefined;
  }

  const { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: totalTokens } =
    usage;

  if (
    promptTokens === undefined &&
    completionTokens === undefined &&
    totalTokens === undefined
  ) {
    return undefined;
  }

  return {
    promptTokens,
    completionTokens,
    totalTokens,
  };
};

export const runClassificationReview = async (
  entries: KevEntrySummary[],
  context?: ClassificationReviewRequestContext,
  options?: { signal?: AbortSignal },
): Promise<ClassificationReviewResponse> => {
  const {
    apiKey,
    apiUrl,
    organisationId,
    model,
    maxEntries,
    temperature,
  } =
    resolveClassificationRuntimeConfig();

  if (!apiKey) {
    return {
      status: "error",
      message:
        "LLM classification review is not configured. Set LLM_AUDIT_API_KEY or OPENAI_API_KEY.",
      code: "missing-api-key",
    };
  }

  const trimmed = entries.slice(0, Math.min(entries.length, maxEntries));

  if (!trimmed.length) {
    return {
      status: "error",
      message: "No entries available for classification review.",
      code: "empty-selection",
    };
  }

  const auditEntries = trimmed.map(toAuditEntry);
  const overview = buildOverview(auditEntries);

  const payload: Record<string, unknown> = {
    model,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: buildUserPrompt(auditEntries, overview, context) },
    ],
    max_completion_tokens: 1200,
  };

  if (typeof temperature === "number") {
    payload.temperature = temperature;
  }

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        ...(organisationId ? { "OpenAI-Organization": organisationId } : {}),
      },
      body: JSON.stringify(payload),
      signal: options?.signal,
    });

    if (!response.ok) {
      const details = await response.text();
      return {
        status: "error",
        message: `LLM request failed with status ${response.status}`,
        code: "llm-http-error",
        details: details.slice(0, 500),
      };
    }

    const completion = (await response.json()) as ChatCompletionResponse;
    const content = completion.choices?.[0]?.message?.content;

    if (!content || typeof content !== "string") {
      return {
        status: "error",
        message: "LLM response did not include textual content.",
        code: "empty-response",
      };
    }

    const extracted = stripJsonFence(content);
    let parsed: unknown;

    try {
      parsed = JSON.parse(extracted);
    } catch (error) {
      return {
        status: "error",
        message: "Failed to parse JSON from LLM response.",
        code: "invalid-json",
        details: extracted.slice(0, 1000),
      };
    }

    const normalised = normaliseSuccess(parsed);

    const success: ClassificationReviewSuccess = {
      status: "ok",
      model: completion.model ?? model,
      usedEntryIds: auditEntries.map((entry) => entry.id),
      issues: normalised.issues,
      taxonomySuggestions: normalised.taxonomySuggestions,
      heuristicImprovements: normalised.heuristicImprovements,
      generalRecommendations: normalised.generalRecommendations,
      overview,
      rawResponseSnippet:
        extracted.length > 4000 ? `${extracted.slice(0, 4000)}…` : extracted,
      usage: buildUsage(completion.usage),
    };

    return success;
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unexpected error during LLM call.";
    return {
      status: "error",
      message: "Failed to request classification review.",
      code: "llm-request-failed",
      details: message,
    };
  }
};
