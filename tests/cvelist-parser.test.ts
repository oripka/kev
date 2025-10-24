import { describe, expect, it } from "vitest";

import {
  resolveCvePath,
  summariseCveRecord,
  type CvelistRecordSummary,
} from "../server/utils/cvelist-parser";

const createSampleRecord = (): Record<string, unknown> => ({
  cveMetadata: {
    cveId: "CVE-2024-12345",
    datePublished: "2024-01-01T00:00:00Z",
    dateUpdated: "2024-02-01T00:00:00Z",
    assignerShortName: "ACME",
  },
  containers: {
    cna: {
      affected: [
        {
          vendor: "Acme",
          product: "Widget",
          versions: [
            { version: "1.0", status: "affected" },
            { lessThan: "2.0", status: "affected", versionType: "custom" },
          ],
          platforms: ["linux", "Linux"],
        },
      ],
      problemTypes: [
        {
          descriptions: [
            {
              description: "CWE-79",
              cweId: "CWE-79",
            },
          ],
        },
      ],
      descriptions: [
        { lang: "en", value: "A sample vulnerability" },
        { lang: "en", value: "A sample vulnerability" },
      ],
      references: [
        { url: "https://example.com/advisory" },
        { url: "https://example.com/advisory" },
      ],
    },
    adp: [
      {
        affected: [
          {
            vendor: "Acme",
            product: "Widget",
            versions: [
              {
                introduced: "1.0",
                fixed: "1.5",
                status: "affected",
              },
            ],
          },
        ],
        problemTypes: [
          {
            descriptions: [
              {
                description: "CWE-89",
                cweId: "CWE-89",
              },
            ],
          },
        ],
        descriptions: [
          { lang: "en", value: "Additional context" },
        ],
        references: [
          { url: "https://example.com/alternate" },
        ],
      },
    ],
  },
});

describe("cvelist parser", () => {
  it("resolves CVE paths using cvelist bucket layout", () => {
    expect(resolveCvePath("CVE-2024-12345")).toBe("cves/2024/1xxx/CVE-2024-12345.json");
    expect(resolveCvePath("CVE-2019-0001")).toBe("cves/2019/0xxx/CVE-2019-0001.json");
  });

  it("summarises CVE records with affected products and metadata", () => {
    const summary: CvelistRecordSummary = summariseCveRecord(
      "CVE-2024-12345",
      createSampleRecord()
    );

    expect(summary.vendors).toHaveLength(1);
    expect(summary.vendors[0]?.products).toHaveLength(1);
    expect(summary.vendors[0]?.products[0]?.versions).toHaveLength(3);
    expect(summary.vendors[0]?.products[0]?.platforms).toEqual(["linux"]);

    expect(summary.cwes.map((item) => item.cweId)).toEqual(["CWE-79", "CWE-89"]);
    expect(summary.references).toEqual([
      "https://example.com/advisory",
      "https://example.com/alternate",
    ]);
    expect(summary.descriptions).toHaveLength(2);
    expect(summary.datePublished).toBe("2024-01-01T00:00:00Z");
    expect(summary.assigner).toBe("ACME");
  });
});
