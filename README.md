# In the Wild catalog

## Overview
In the Wild is a Nuxt 4 application that aggregates the CISA Known Exploited Vulnerabilities (KEV) list, ENISA advisories, historic exploitation reports, public proof-of-concept feeds, and vulnerability marketplace signals into a single searchable catalog. The interface highlights actively exploited CVEs, trending vendors and products, and market activity so responders can triage and prioritise patching efforts quickly.

## Architecture
### Frontend
- Nuxt 4 + Nuxt UI power the catalog UI under `app/`, with TanStack Table for paging and VueUse utilities for composables.
- Shared composables such as `useKevData` fetch catalog summaries (counts, heatmap, timeline, market insights) and expose them to the page and supporting components.
- Reusable utilities encapsulate query parsing (`app/utils/queryParams.ts`) and timeline bucketing (`app/utils/timeline.ts`) so the router, API client, and widgets stay in sync.

### Server APIs
- Nitro server routes under `server/api/` expose catalog data, admin utilities, and ingestion hooks.
  - `GET /api/kev` drives the main catalog view, applying dynamic filters, full-text search, vendor/product heatmaps, and pre-computed timeline buckets via Drizzle ORM.
  - `POST /api/fetchKev` orchestrates feed ingestion, enrichment, and catalog rebuilds during development runs.
  - `POST /api/admin/reclassify` re-enriches cached vulnerability entries and rebuilds the catalog after heuristics change.

### Data processing
- Feed importers normalise raw entries (CVEList, ENISA, Metasploit, GitHub PoCs, marketplace) and persist them in `vulnerability_entries` before rebuilding derived tables.
- `server/utils/catalog.ts` materialises aggregated catalog tables (`catalog_entries`, `catalog_entry_dimensions`, `catalog_entries_fts`) and computes market signals for each product.
- Classification heuristics live in `~/utils/classification` and are re-run during reclassification to keep cached dimensions fresh.

### Database
- Drizzle ORM targets SQLite locally and Cloudflare D1 in production; connection helpers auto-detect bindings.
- Schema definitions live in `server/database/schema.ts` and include the denormalised catalog, FTS mirror, vulnerability entry cache, product catalog, market offers, and metadata tables.
- Migrations under `server/database/migrations/` (SQL + JSON snapshots) must be applied with `pnpm db:migrate` for local sqlite or exported with `pnpm db:deploy` for D1 deployments.

## Ingestion workflow
1. Admin triggers `/api/fetchKev` (development-only) specifying mode, source selection, and strategy. The handler schedules tasks for each feed (KEV, historic, ENISA, Metasploit, PoC, market).
2. Each feed loader fetches data, enriches entries via CVEList heuristics, calculates differences, and writes back to `vulnerability_entries`, related categories, and impact tables.
3. After ingestion, `rebuildCatalog` recomputes aggregated catalog tables, heatmap counts, FTS documents, and metadata (bounds, entry counts).
4. `rebuildProductCatalog` and marketplace helpers attach market availability metrics for tracked products.
5. Clients consume the refreshed catalog via `useKevData`, which exposes entries, counts, heatmap groups, timelines, and market overviews with automatic polling for imports.

## Local development
1. Install dependencies with `pnpm install`.
2. Apply database migrations: `pnpm db:migrate` (sqlite) or `pnpm db:deploy` to push snapshots to a Cloudflare D1 instance.
3. Start the Nuxt dev server with `pnpm dev` (note: import jobs are restricted to development mode).
4. Trigger a catalog import via `POST /api/fetchKev` with a valid `ADMIN_API_KEY` header to populate data locally.

## Environment configuration
| Variable | Purpose |
| --- | --- |
| `ADMIN_API_KEY` | Shared secret checked by admin APIs (imports, reclassification). |
| `DB` | Cloudflare D1 binding name for production deployments; absent values fall back to local SQLite. |
| `NVD_API_KEY` | Optional token for CVSS enrichment when `CVSS_FETCH_ENABLED` is toggled on. |
| `LLM_AUDIT_API_URL`, `LLM_AUDIT_API_KEY`, `LLM_AUDIT_ORG_ID`, `LLM_AUDIT_MODEL`, `LLM_AUDIT_MAX_ENTRIES`, `LLM_AUDIT_TEMPERATURE`, `OPENAI_API_KEY` | Configure the optional LLM-powered classification audit surfaced in the UI. |
| `NUXT_DISABLE_GITHUB_POC_IMPORT`, `DISABLE_GITHUB_POC_IMPORT`, `NUXT_PUBLIC_DISABLE_GITHUB_POC_IMPORT` | Disable the GitHub PoC feed to reduce import time or DB size. |
| `NUXTHUB_D1_DATABASE`, `NUXTHUB_D1_DUMP`, `NUXTHUB_D1_CHUNK_BYTES`, `NUXTHUB_LOCAL_D1_PATH`, `LOCAL_SQLITE_PATH`, `DATABASE_PATH` | Override export paths when deploying snapshots to Cloudflare D1. |

## Deployment notes
- The site statically generates via Nuxt and serves dynamic catalog APIs through Nitro functions. Provide the `DB` binding (Cloudflare D1) and secrets above when deploying to Cloudflare Workers/Pages.
- Run `pnpm db:deploy` during CI/CD to export the local sqlite schema/data to D1 using `scripts/export-to-d1.mjs`.
- For self-hosted sqlite deployments, ensure the `data/` directory is writable so the bundled migrator can apply schema changes on first boot.

## Data caches
Importer jobs keep sparse clones of upstream feeds under `data/cache/` to accelerate re-runs:
- `data/cache/cvelist` — shallow clone of CVEProject/cvelistV5 for CVE metadata enrichment; refresh via KEV imports or `POST /api/admin/refresh-cvelist`.
- `data/cache/metasploit` — sparse checkout of the Metasploit Framework repository for module metadata.
Metadata about the most recent refresh is stored in `kev_metadata` (`cvelist.lastCommit`, `cvelist.lastRefreshAt`) for observability.
