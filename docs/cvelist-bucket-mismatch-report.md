# CVEList bucket mismatch breaks enrichment for high-sequence CVEs

## Summary
CVE-2025-47916 (Metasploit "Invision Community 5.0.6 customCss RCE") shows up in the catalog as a Microsoft Windows issue even though CVEList correctly documents it as affecting Invision Community. The import pipeline fails to read the CVEList JSON, so the KEV and Metasploit entries never receive the canonical vendor/product pair and we fall back to a misclassified value.

## Impact
- Any CVE with a sequence number above 9,999 is looked up under `cves/<year>/4xxx/…`, so CVEList lookups fail for the entire 40k–49k range (and analogous ranges for other prefixes).
- Without a CVEList hit we retain whatever vendor/product came from KEV or our heuristics. In this case the record inherits a stale "Microsoft" vendor, so dashboards and filters blame the wrong vendor and product, and enrichment like affected product lists remains empty.

## Root cause
- `resolveCvePath` only keeps the first digit of the numeric sequence when building the bucket path (e.g. `CVE-2025-47916` → `4xxx`). CVEProject’s `cvelistV5` repository stores five-digit sequences under `47xxx`, so the loader tries to read a file that does not exist and the enrichment falls back to the base entry. 【F:server/utils/cvelist-parser.ts†L432-L468】
- The unit test for path resolution only exercises four-digit IDs (`1xxx` and `0xxx` buckets). Because we never test a five-digit CVE, the regression slipped through unnoticed. 【F:tests/cvelist-parser.test.ts†L35-L46】

## Next steps
1. Update `resolveCvePath` to follow the official bucket layout for every sequence length (e.g. two digits for 10k–99k, three digits for 100k+, etc.).
2. Extend the parser test suite with coverage for at least one five-digit CVE (e.g. `CVE-2025-47916` → `47xxx`) and a six-digit CVE to prevent future regressions.
3. After fixing the lookup, re-run the KEV and Metasploit imports so the CVEList enrichment overwrites the incorrect Microsoft vendor with the Invision Community data.
