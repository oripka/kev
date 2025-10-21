# Vendor and Product Matching Report

## Overview
This report documents how vendor and product identifiers are normalized across the Known Exploited Vulnerabilities (KEV) feed, related CISA data, historic exploit intelligence, and external exploit sources. It also outlines the planned workflow for forthcoming bug bounty and exploit broker integrations and highlights the gaps we must close to make the mapping bulletproof.

## Normalization Pipeline

### Vendor normalization
* The `normaliseVendorProduct` utility standardizes incoming names by trimming whitespace, stripping corporate suffixes (Inc., Ltd., GmbH, etc.), and forcing consistent casing so that variants such as “MICROSOFT CORPORATION” collapse to “Microsoft.”
* When the vendor field is missing or ambiguous ("N/A", "Unknown", "Multiple vendors"), the helper infers a vendor from the product text (e.g., product strings that contain "Windows" become “Microsoft”).
* A canonical `vendorKey` slug is generated from the normalized label to provide a stable join key across imports.

These behaviors ensure that feeds already align on the base vendor name—so "Microsoft Windows" and "Windows" both normalize to the same vendor identifier.【F:app/utils/vendorProduct.ts†L1-L171】【F:app/utils/vendorProduct.ts†L458-L506】

### Product normalization
* Vendor tokens are removed from the product name to avoid duplicates such as “Microsoft Microsoft Exchange.”
* Noise like catalog tags (“tracked by CISA”), range descriptors (“prior to 15.0”), comparative suffixes, platform notes, and repeated whitespace is stripped.
* Platform-specific casing fixes (iOS, macOS, tvOS, etc.) and Linux kernel special cases consolidate common aliases.
* Version keywords, dotted version strings, build/release identifiers, and parenthetical suffixes are removed, but plain numeric tokens (e.g., “Windows 10 1909”) remain.
* A `productKey` slug pairs the vendor slug with the normalized product label to act as the primary matching key.

The result is a cleaned product label and deterministic slug, but there is no dedicated field for product family or parsed version metadata, so variant strings like “Windows 7” and “Windows 10 1909” continue to generate distinct keys.【F:app/utils/vendorProduct.ts†L202-L456】【F:app/utils/vendorProduct.ts†L458-L506】 The numeric removal logic targets dotted or annotated versions, which means standalone numbers persist today.【F:app/utils/vendorProduct.ts†L183-L191】

## Source Ingestion Coverage

### CISA KEV feed
The KEV importer normalizes every `vendorProject` and `product` before upserting rows, guaranteeing that CISA-provided names share the same keys as other sources that describe the same software.【F:server/api/fetchKev.post.ts†L188-L225】

### ENISA exploited catalog
ENISA entries use the same helper when the API exposes vendor/product pairs. This keeps European threat intelligence aligned with the KEV catalog and reuses the identical vendor/product keys for joins.【F:server/utils/enisa.ts†L137-L198】

### Historic exploited dataset
Historic research data is normalized in the same way during import, preserving consistent keys for long-tail CVEs sourced outside of CISA or ENISA.【F:server/utils/historic.ts†L50-L91】

### Metasploit modules
Metasploit rarely provides explicit vendor metadata, so the importer guesses a vendor/product based on module platforms, file paths, and descriptive text. Platform keywords ("windows", "osx", "android", etc.) are mapped to canonical vendor/product pairs, and any successful guess is normalized through the shared utility. After ingest, the importer optionally overrides its guess with higher-confidence vendor/product labels already stored for the same CVE—favoring KEV data first—so that community exploit metadata follows the same normalization as the primary feeds.【F:server/utils/metasploit.ts†L840-L1079】

## Planned Bug Bounty and Exploit Broker Alignment
The market-intelligence roadmap introduces dedicated tables (`market_offers`, `software_catalog`, and `offer_cve_links`) that rely on the exact `normaliseVendorProduct` pipeline to align bug bounty scopes and exploit broker offers with the CVE catalog. The plan calls for creating or reusing canonical vendor/product rows in `software_catalog`, linking offers to CVEs via normalized keys, and backfilling the catalog from existing CVE product pairs to guarantee consistent joins across sources.【F:docs/vulnerability-market-intel-plan.md†L3-L133】

## Handling Windows and Version Variants
The current normalization step removes dotted or annotated versions but keeps standalone numbers, so:
* “Windows 10 1909” and “Windows 10 2004” normalize to distinct product labels because the trailing numbers remain.
* “Windows 2012 R2” retains the “2012 R2” suffix because only explicit build phrases and dotted versions are stripped.
* “Windows 7” and “Windows 8” normalize separately for the same reason.

This behavior ensures that specific build identifiers are preserved when the source explicitly differentiates them, but it prevents automatic consolidation into a single “Windows” family without additional logic.【F:app/utils/vendorProduct.ts†L183-L456】

## Gaps and Requirements for Bulletproof Matching
1. **Introduce explicit product family and version metadata.** Because the normalized output only exposes `label` and `key`, we cannot express that “Windows 10 1909” belongs to the “Windows 10” family or to “Microsoft Windows” more broadly without relying on string prefixes. Extending the normalization utility to emit structured fields (e.g., `family`, `majorVersion`, `rawVersionTokens`) and storing them alongside the slug would let us collapse variants while still reporting precise builds.【F:app/utils/vendorProduct.ts†L1-L11】【F:app/utils/vendorProduct.ts†L458-L506】
2. **Maintain a curated synonym dictionary.** Heuristics already cover Linux and some Microsoft kernel aliases, but they do not map Windows Server releases ("2012 R2" vs. "2012") or desktop build numbers. A maintained lookup table layered on top of the normalization results could collapse known Windows, Office, and Azure SKUs into canonical products before slugging.【F:app/utils/vendorProduct.ts†L343-L388】
3. **Capture raw version ranges separately from normalized labels.** Keeping the original version expressions in dedicated columns would let analytics handle “prior to 1909” or “<= 2004” ranges without losing context after normalization strips those descriptors.【F:app/utils/vendorProduct.ts†L212-L455】
4. **Leverage the software catalog for cross-source overrides.** The planned `software_catalog` table gives us a home for canonical vendor/product rows; enriching it with additional columns (family name, platform, lifecycle status) would provide deterministic joins for bug bounty and broker offers while preserving provenance to KEV-normalized values.【F:docs/vulnerability-market-intel-plan.md†L73-L133】
5. **Keep manual review hooks.** Even with stronger normalization, we still need an override workflow similar to the Metasploit importer’s “prefer KEV” rule to resolve ambiguous cases and enforce consistency when automated matching disagrees.【F:server/utils/metasploit.ts†L1003-L1079】

Implementing these additions will let us automatically align variants such as “Windows 10 1909” with the broader Windows family, while still tracking the specific editions and build numbers that operators and buyers care about, yielding actionable, consolidated analytics across KEV, CISA, bug bounty programs, and exploit brokers.
