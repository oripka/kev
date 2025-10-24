# Ingestion Pipeline Transparency Report

## Overview
Our ingestion pipeline consolidates five primary data sources—CISA KEV, the curated historic exploit list, ENISA's exploited vulnerabilities API, Metasploit modules, and market intelligence snapshots—into a unified catalog. A single `/api/fetchKev` job orchestrates each run, toggling between *force* downloads and *cache* reuse flags based on the admin action, then fans out to the appropriate importer for every enabled source.【F:server/api/fetchKev.post.ts†L123-L212】【F:server/api/fetchKev.post.ts†L572-L620】 Each importer produces normalized base entries, enriches them with CVEList metadata and in-house classifiers, and persists the results to `vulnerabilityEntries` before the catalog tables are rebuilt for analytics and search.【F:server/api/fetchKev.post.ts†L224-L552】【F:server/api/fetchKev.post.ts†L622-L695】

### Caching behaviour
All network-bound importers share a filesystem cache keyed by feed name. The helper only refetches a dataset when the TTL has expired or the admin chooses *Import latest data*; otherwise it can reuse fresh or explicitly stale payloads without hitting the upstream source.【F:server/utils/cache.ts†L1-L107】【F:server/api/fetchKev.post.ts†L189-L212】【F:server/utils/enisa.ts†L223-L304】

## Source ingestion details

### CISA Known Exploited Vulnerabilities (KEV)
1. Download (or reuse cached) JSON from CISA’s feed, respecting the selected import mode (`force`, `auto`, or `cache`).【F:server/api/fetchKev.post.ts†L123-L212】
2. Run every vulnerability through `normaliseVendorProduct`, which supplies fallback vendor/product labels even when CISA publishes `Unknown` or missing data, then populate base entry metadata, CVSS placeholders, and notes.【F:server/api/fetchKev.post.ts†L224-L272】
3. Merge cached CVSS metrics with any new scores retrieved via NVD, then enrich each base entry with CVEList impacts and our domain/exploit/vulnerability classifiers before writing a fully denormalized record to SQLite, including per-entry category rows for analytics.【F:server/api/fetchKev.post.ts†L283-L552】

### Historic exploited dataset
1. Load the local `historic.json`, normalize vendor/product hints using the same helper, and derive a year-based ISO timestamp for temporal analytics.【F:server/utils/historic.ts†L56-L108】【F:server/utils/historic.ts†L152-L175】
2. Reuse CVEList enrichment to attach impact metadata, then persist enriched entries and category dimensions to the cache tables with progress telemetry identical to the KEV importer.【F:server/utils/historic.ts†L172-L312】

### ENISA exploited catalog
1. Page through ENISA’s API (or reuse cache), aggregating unique records by ENISA UUID and normalizing vendor/product labels.【F:server/utils/enisa.ts†L223-L304】
2. Enrich and persist entries the same way as other sources, while storing ENISA-specific timestamps and metadata for change detection.【F:server/utils/enisa.ts†L308-L454】

### Metasploit modules
1. Parse every exploit module, guess vendor/product pairs from module metadata, then normalize them with the shared helper before creating base entries tied to module paths and commits.【F:server/utils/metasploit.ts†L1162-L1224】
2. After initial normalization, prefer catalogued vendor/product labels from KEV, historic, or ENISA imports when they exist so the community exploit data aligns with our canonical catalog keys.【F:server/utils/metasploit.ts†L1240-L1305】

### Market intelligence snapshots
Market data piggybacks on the same orchestrator: `/api/fetchKev` delegates to `importMarketIntel`, recording offer/program/product counts alongside other feeds so catalog rebuilds stay in sync with the rest of the ingest cycle.【F:server/api/fetchKev.post.ts†L589-L695】

## Classification and catalog assembly
*Classification pipeline.* After CVEList enrichment each entry passes through `enrichEntry`, which assigns domain categories, exploit layers, vulnerability classes, and an `internetExposed` flag that drive the downstream filters and badges.【F:server/api/fetchKev.post.ts†L374-L552】【F:app/utils/classification.ts†L2997-L3009】

*Catalog rebuild.* Every import (and the standalone reclassify job) calls `rebuildCatalog` and `rebuildProductCatalog` to collapse `vulnerabilityEntries` into analytics-friendly tables and materialized product summaries.【F:server/api/fetchKev.post.ts†L622-L695】【F:server/api/admin/reclassify.post.ts†L19-L52】 Because the reclassify endpoint only rebuilds these aggregates, it cannot incorporate new heuristics unless the underlying entries themselves are refreshed through a full import run.【F:server/api/admin/reclassify.post.ts†L19-L58】

## Admin actions and their effects

| Admin action | Mode sent to `/api/fetchKev` | Data sources touched | Vendor/product impact | Notes |
| --- | --- | --- | --- | --- |
| **Import latest data** | `mode: "force"` for all sources (or a single chosen source) | Triggers live downloads for KEV, historic, ENISA, Metasploit, and market feeds, then rebuilds catalogs | Re-runs normalization and classification for every refreshed entry | Use when upstream feeds changed or heuristics were updated and a clean re-import is needed.【F:app/pages/admin.vue†L322-L343】【F:app/composables/useKevData.ts†L230-L264】【F:server/api/fetchKev.post.ts†L123-L695】 |
| **Use cached feed / Reimport cached data** | `mode: "cache"` | Replays cached payloads for the selected source(s); still executes enrichment and catalog rebuilds | Normalization runs on cached payloads only; vendor/product corrections reflect whatever the cache contains | Faster when testing UI changes, but stale payloads keep any existing vendor/product mislabels.【F:app/pages/admin.vue†L334-L378】【F:server/api/fetchKev.post.ts†L123-L620】 |
| **Reclassify cached data** | Calls `/api/admin/reclassify` (no fetch) | Only rebuilds catalog aggregates from already-saved entries | Does **not** rerun `normaliseVendorProduct` or `enrichEntry`, so vendor/product errors persist | Currently insufficient for correcting misclassification bugs—requires a full import to recalculate entries.【F:app/pages/admin.vue†L588-L607】【F:server/api/admin/reclassify.post.ts†L19-L58】 |

## Data quality concerns

### Vendor and product attribution
Every importer funnels through `normaliseVendorProduct`, which defaults ambiguous values to "Unknown," applies a finite set of regex overrides, and only infers vendors from a handful of keyword patterns (e.g., Windows → Microsoft, iOS/macOS → Apple).【F:app/utils/vendorProduct.ts†L1-L139】 When upstream feeds provide sparse strings—or when products lack Microsoft/Apple-style keywords—the helper cannot confidently assign the right vendor or family, leading to the inaccurate catalog labels we observe across sources.

### Cascade of mislabels across sources
Because all sources share the same normalization helper, a misidentified vendor/product in one feed propagates when Metasploit or other imports try to align with existing catalog rows—the override logic simply copies whatever is already stored for that CVE.【F:server/utils/metasploit.ts†L1240-L1305】 A mistaken key therefore becomes self-reinforcing until a human-curated override or revised heuristic corrects it at the source.

### Reclassification limitations
Running **Reclassify cached data** cannot repair these issues: the endpoint only rebuilds aggregate tables from existing rows and never re-executes `enrichEntry` or vendor/product normalization, so any classifier or override improvements are ignored until a full import refreshes the row-level cache.【F:server/api/admin/reclassify.post.ts†L19-L58】

### Transparency going forward
Given the shared helper and caching behaviour, we recommend:
- Prioritizing full *Import latest data* runs immediately after updating vendor/product overrides or classification heuristics so corrected labels propagate to every source.
- Expanding the inference logic (or adding curated mappings) for the vendors and product families that are currently misclassified, especially those without strong keyword cues.
- Enhancing the reclassify endpoint to reload raw entries and rerun normalization so data-quality fixes can be rolled out without lengthy imports.
