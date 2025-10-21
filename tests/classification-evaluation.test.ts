import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { enrichEntry, type KevBaseEntry } from "~/utils/classification";
import type {
  CatalogSource,
  CvssSeverity,
  KevDomainCategory,
  KevExploitLayer,
  KevVulnerabilityCategory,
} from "~/types";

const vendorNoiseTokens = new Set([
  "inc",
  "incorporated",
  "corporation",
  "corp",
  "company",
  "co",
  "llc",
  "ltd",
  "limited",
  "plc",
  "gmbh",
  "ag",
  "sa",
  "sarl",
  "srl",
  "bv",
  "nv",
  "oy",
  "oyj",
  "kg",
  "kk",
  "pte",
  "pty",
  "spa",
  "llp",
  "lp",
  "holdings",
  "holding",
  "group",
  "systems",
  "the",
]);

const normaliseKeySegment = (value: string) =>
  value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");

const makeVendorKey = (value?: string | null) => {
  const normalized = normaliseKeySegment(value ?? "");

  if (!normalized) {
    return "";
  }

  const tokens = normalized.split(" ");
  const filtered = tokens.filter((token) => !vendorNoiseTokens.has(token));

  if (!filtered.length) {
    return normalized;
  }

  return filtered.join(" ");
};

const makeProductKey = (value?: string | null) => normaliseKeySegment(value ?? "");

type ExpectationList<T> = {
  includes?: T[];
  excludes?: T[];
  exact?: T[];
};

type EntryInput = {
  cveId: string;
  vendor: string;
  product: string;
  vulnerabilityName: string;
  description: string;
  cvssVector?: string;
  cvssVersion?: string;
  cvssScore?: number;
  cvssSeverity?: CvssSeverity;
  datePublished?: string | null;
  dateUpdated?: string | null;
};

type ClassificationExpectations = {
  internetExposed?: boolean;
  domainCategories?: ExpectationList<KevDomainCategory>;
  exploitLayers?: ExpectationList<KevExploitLayer>;
  vulnerabilityCategories?: ExpectationList<KevVulnerabilityCategory>;
};

type ClassificationTestCase = {
  id: string;
  title: string;
  entry: EntryInput;
  expect: ClassificationExpectations;
};

const datasetPath = fileURLToPath(
  new URL("./fixtures/classification-evaluation.json", import.meta.url)
);

const rawData = readFileSync(datasetPath, "utf8");
const evaluationCases = JSON.parse(rawData) as ClassificationTestCase[];

const defaultSources: CatalogSource[] = ["kev"];

const createBaseEntry = (input: EntryInput): KevBaseEntry => {
  const vendor = input.vendor;
  const product = input.product;
  const cveId = input.cveId;

  return {
    id: `${cveId}::${makeProductKey(product)}`,
    cveId,
    sources: defaultSources,
    vendor,
    vendorKey: makeVendorKey(vendor),
    product,
    productKey: makeProductKey(product),
    vulnerabilityName: input.vulnerabilityName,
    description: input.description,
    requiredAction: null,
    dateAdded: "2024-01-01",
    dueDate: null,
    ransomwareUse: null,
    notes: [],
    cwes: [],
    cvssScore: input.cvssScore ?? null,
    cvssVector: input.cvssVector ?? null,
    cvssVersion: input.cvssVersion ?? null,
    cvssSeverity: input.cvssSeverity ?? null,
    epssScore: null,
    assigner: null,
    datePublished: input.datePublished ?? null,
    dateUpdated: input.dateUpdated ?? null,
    exploitedSince: null,
    sourceUrl: null,
    references: [],
    aliases: [],
    metasploitModulePath: null,
    metasploitModulePublishedAt: null,
    internetExposed: false,
    marketSignals: null,
  };
};

const assertExpectation = <T extends string>(
  actual: T[],
  expectation?: ExpectationList<T>
) => {
  if (!expectation) {
    return;
  }

  if (expectation.exact) {
    const expectedSet = new Set(expectation.exact);
    expect(actual.length).toBe(expectedSet.size);
    for (const expected of expectedSet) {
      expect(actual).toContain(expected);
    }
  }

  if (expectation.includes) {
    for (const value of expectation.includes) {
      expect(actual).toContain(value);
    }
  }

  if (expectation.excludes) {
    for (const value of expectation.excludes) {
      expect(actual).not.toContain(value);
    }
  }
};

describe("classification evaluation suite", () => {
  for (const testCase of evaluationCases) {
    it(testCase.title, () => {
      const entry = createBaseEntry(testCase.entry);
      const enriched = enrichEntry(entry);

      assertExpectation(enriched.domainCategories, testCase.expect.domainCategories);
      assertExpectation(enriched.exploitLayers, testCase.expect.exploitLayers);
      assertExpectation(
        enriched.vulnerabilityCategories,
        testCase.expect.vulnerabilityCategories
      );

      if (testCase.expect.internetExposed !== undefined) {
        expect(enriched.internetExposed).toBe(testCase.expect.internetExposed);
      }
    });
  }
});
