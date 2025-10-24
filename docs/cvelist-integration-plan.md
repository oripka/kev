# CVEList v5 integration plan

## Objectives

- Use the official [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) repository as the authoritative dataset for vendor, product, version, and classification details when importing CVE records (KEV, ENSISA, historic, Metasploit, and future feeds).
- Cache the upstream repository under `data/cache` so imports can re-use a local shallow clone and update it incrementally.
- Normalise the affected product data so that every CVE in `vulnerability_entries` and the derived `catalog_entries` tables consistently exposes:
  - canonical vendor/product keys derived from CVEList metadata,
  - the list of affected product variants and version constraints,
  - CWE/problem-type identifiers for classification.
- Keep existing fuzzy matching logic as a fallback only when CVEList has `"vendor": "n/a"`, empty strings, or the record is missing.

## Repository caching strategy

1. **Directory layout**
   - Mirror the metasploit cache layout: `data/cache/cvelist` (directory) → `data/cache/cvelist/cvelistV5` (working tree).
   - Ensure `.gitkeep` is unnecessary; the directory is created dynamically and excluded from Git.

2. **Sync helper (`server/utils/cvelist.ts`)**
   - Extract the generic git helpers from `server/utils/metasploit.ts` into `server/utils/git.ts` (e.g. `runGit`, `pathExists`, `ensureDir`, `syncSparseRepo`).
   - Implement `syncCvelistRepo({ useCachedRepository?: boolean })` that:
     - clones with `--depth=1 --filter=blob:none --sparse` on first run,
     - runs `git sparse-checkout set cves` so only CVE JSON is materialised,
     - on subsequent runs performs `fetch --depth=1 origin main`, `reset --hard origin/main`, and `clean -fdx`, unless `useCachedRepository` is true (for offline imports),
     - returns `{ commit: string | null, updated: boolean }` for telemetry.
   - Reuse the helper inside import jobs with the same allow-stale semantics already used for KEV/metasploit (respect the `mode` flags in `fetchKev.post.ts`).

3. **Update metadata**
   - Store the current commit hash in `metadata` under `cvelist.lastCommit` so the UI can display when the vendor/product catalogue was last refreshed.

## Parsing CVE records

Create `server/utils/cvelist-parser.ts` to expose pure functions that accept raw CVE JSON and emit normalized structures. Key tasks:

1. **File discovery**
   - `resolveCvePath(cveId: string)` → derive `cves/<year>/<range>/CVE-YYYY-NNNN.json` path using the CVE ID to avoid scanning the full tree.
   - `readCveRecord(cveId)` → read & parse JSON (surface descriptive errors when missing or invalid JSON).

2. **Affected products**
   - Prefer `containers.cna.affected` entries:
     - Normalise vendor/product strings (trim, collapse whitespace, drop corporate suffix noise via existing helpers in `classification.ts`).
     - Expand entries with multiple products in a single `product` string by splitting on commas only if the CVE uses list formatting (guard against legitimate commas inside names by checking for `, ` patterns).
     - Preserve `versions` array with fields `{ version, lessThan, lessThanOrEqual, greaterThan, status, versionType }`.
   - If `affected` is empty, fall back to:
     - `containers.adp[].affected`,
     - `containers.cna.cpeApplicability[].nodes[].cpeMatch[]`, parsing the vendor/product from the CPE URI and capturing the version start/end bounds.
   - Deduplicate vendor/product combos (case-insensitive) while merging version ranges and status flags.

3. **Problem types / CWE**
   - Collect CWE IDs and descriptive strings from both CNA and ADP containers.
   - Emit `{ cweId?: string, description: string, source: 'cna' | 'adp' }` entries to feed into classification.

4. **Additional metadata**
   - Extract `datePublished`, `dateUpdated`, `references`, and `descriptions` to enrich existing import flows when missing.
   - Capture `assignerShortName` for provenance.

5. **Parser output shape**
   ```ts
   interface CvelistRecordSummary {
     cveId: string;
     vendors: Array<{
       vendor: string;
       vendorKey: string;
       products: Array<{
         product: string;
         productKey: string;
         versions: Array<NormalisedVersion>;
         platforms: string[];
       }>;
     }>;
     cwes: Array<{ cweId?: string; description: string; source: 'cna' | 'adp' }>;
     references: string[];
     descriptions: Array<{ lang: string; value: string; source: 'cna' | 'adp' }>;
     datePublished?: string;
     dateUpdated?: string;
     assigner?: string;
   }
   ```
   - `NormalisedVersion` should normalise range semantics (`introduced`, `fixed`, etc.) so we can later pivot to UI-friendly phrasing.

## Database schema changes

1. **`vulnerability_entries` table**
   - Add `vendorKey` / `productKey` columns to store the primary match chosen for the entry (useful for quick lookups & joins).
   - Add JSON columns for denormalised data:
     - `affectedProducts` (JSON string array of `{ vendor, product, vendorKey, productKey, versions, platforms }`).
     - `problemTypes` (JSON array of `{ cweId, description, source }`).
   - We jsut overwrite / reimport everything again...Dont': Backfill existing rows with empty arrays to maintain NOT NULL constraints (or make the new columns nullable with sensible defaults).

2. **New join table for multi-product relationships**
   - `vulnerability_entry_impacts` with columns:
     - `entryId` (FK → `vulnerability_entries.id`),
     - `vendor`, `vendorKey`, `product`, `productKey`,
     - `status` (`affected`, `unaffected`, etc.),
     - `versionRange` (serialized JSON for `{ introduced?, fixed?, lessThan?, lessThanOrEqual? }`),
     - `source` (`cna`, `adp`, `cpe`),
     - primary key on `(entryId, vendorKey, productKey, status, versionRangeHash)` to avoid duplicates.
   - This table powers product-level analytics and supports future UI facets like "show all affected versions".

3. **Migration plan**
   - Create a drizzle migration that adds the new columns & table, with default values for legacy rows (empty JSON arrays and NULL keys).
   - Update `server/database/schema.ts` and any TypeScript types that assume `vulnerability_entries` only tracks single vendor/product strings.

## Import flow updates

1. **CVE lookup cache**
   - Build a memoized helper (`loadCvelistRecord(cveId, options)`) that consults:
     1. An in-memory LRU (per import run) keyed by CVE ID.
     2. Optionally a persisted cache file `data/cache/cvelist-index.json` storing `{ cveId, vendorKey, productKey, lastUpdated }` for previously parsed records. This avoids re-reading JSON on incremental imports.
   - On each import run, ensure `syncCvelistRepo` is invoked before reading any CVE records unless `mode === 'cache'`.

2. **KEV importer (`server/api/fetchKev.post.ts`)**
   - After constructing the base entry, call `loadCvelistRecord(cveId)`:
     - Replace empty/placeholder vendor or product values with the first canonical match from CVEList.
     - Populate `entry.cwes` from the CVEList summary when KEV lacks CWE data.
     - Merge `references` & `descriptions` when KEV is sparse.
     - Store `affectedProducts` JSON & insert rows into `vulnerability_entry_impacts` for downstream analytics.
   - Update import progress logs to report how many CVEList lookups succeeded vs. fell back to heuristics.

3. **Historic / ENSISA / Metasploit**
   - Each importer should request the CVEList summary before falling back to heuristics. For datasets that provide only a CVE ID, the CVEList data becomes the primary vendor/product source.
   - Keep the existing `matchExploitProduct` and curated hints as override layers when CVEList has ambiguous or `n/a` data.

4. **Error handling**
   - Missing CVE file: log once per import (with `markTaskError`) and fallback to current heuristics without failing the entire batch.
   - Invalid JSON: report to telemetry, skip the record, but continue the import.

## Classification updates

1. **Problem type to category mapping**
   - Extend `app/utils/classification.ts` to accept an optional list of CVEList problem types (`{ cweId, description }`).
   - When `cweId` is present, use it to:
     - Populate the `cwes` array for catalog entries.
     - Drive the vulnerability category detection (e.g. map CWE-787 to "Memory Corruption" domain). Maintain an internal mapping table keyed by CWE ID and fall back to textual matching on the description (e.g. "Elevation of Privilege").
   - Ensure the new logic does not create duplicate category entries—deduplicate by category key before storing.

2. **Vendor/product keys**
   - Reuse the normalization helpers already defined in `classification.ts` (consider exporting them if needed) to keep consistent key generation between CVEList parsing and catalog building.

3. **Testing hooks**
   - Add unit tests for the parser and classification adjustments (fixtures with examples similar to CVE-2021-24035 and CVE-2024-20669).

## Performance & maintenance

- Parsing only the CVEs referenced during an import keeps runtime manageable (~10k lookups at worst). The sparse checkout prevents pulling the entire repository history.
- Provide an admin action (CLI or API) to refresh the CVEList cache on demand without re-running the full import (e.g. `POST /api/admin/refresh-cvelist`). This can reuse `syncCvelistRepo` and store the commit hash in metadata.
- Document the cache directory in the README or ops docs so operators know how to purge/update it manually.

## Edge cases & fallback logic

- When CVEList uses `"vendor": "n/a"`, treat that as missing data and allow existing heuristics/curated mappings to fill the gap.
- For CVEs with multiple affected vendors, prioritise the vendor/product pair that matches the importing feed (e.g. if KEV vendor matches one of the CVEList vendors, keep that as primary but still store all others in `affectedProducts`).
- Ensure we do not insert duplicate `vulnerability_entry_impacts` rows when the same vendor/product appears in both CNA and ADP containers—merge by `(vendorKey, productKey, versionRange)`.

## Deliverables checklist

- [x] `server/utils/git.ts` with shared git helpers.
- [x] `server/utils/cvelist.ts` for repo sync + lookup cache.
- [x] `server/utils/cvelist-parser.ts` with unit tests and fixtures.
- [x] Database migration adding CVEList columns and the impacts join table.
- [x] Import pipeline updates (KEV, ENSISA, historic, Metasploit enrichment).
- [x] Make sure to srufacne this in the admin ui as well
- [x] Classification updates for problem types/CWEs.
- [x] Documentation updates describing the new dependency & cache location.
