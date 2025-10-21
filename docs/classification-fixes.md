# ✅ Classification Fix Log Summary

> Short log of verified fixes and remaining actions to avoid repeating prior misclassifications.

## Findings Summary
- [x] **Cisco IOS misclassified as client:**  
  `ios` token matched Cisco network OS; now replaced with contextual Apple-only patterns and negative guards for `Cisco IOS` / `IOS XE` / `IOS XR`.

- [x] **Mobile MDM servers misclassified as clients:**  
  `mobile` token required context (`mobile app`, `mobile device`) or handled by product taxonomy (MobileIron/EPMM).

- [x] **Local File Inclusion (LFI) mapped to client execution:**  
  LFI tokens removed from client rules and routed into server-side exploit detection.

## Fixes Implemented
- [x] Replaced bare `ios` token with contextual Apple-only expressions.  
- [x] Added explicit negative matches for Cisco IOS variants.  
- [x] Guarded `mobile` keyword; treat MDM platforms as server-side.  
- [x] Removed LFI from client patterns and added server LFI list.  
- [x] Fixed catch-all `clientApplicationPatterns` regex to require actual tokens.  
- [x] Tightened file/attachment heuristics — only count when user action verbs appear.  
- [x] Strengthened tie-breaker — prefer server if equal or server signals exist.  
- [x] Introduced curated vendor/product taxonomy to seed `domainCategories`.  
- [x] Rebalanced scoring: +2 client bonus only when combined evidence exists.  
- [x] Added `Mixed / Needs Review` category for ambiguous cases.  
- [x] Stopped `/api/fetchKev` from caching incorrect client labels.  
- [x] Normalized RCE labelling (memory vs non-memory not duplicated).  
- [x] Adjusted `management console` regex to avoid mislabelling desktop MMC.  
- [x] Added server-side LFI regex feeding domain + exploit scoring.
- [x] Dataset whitelist/blacklist now used to override raw regex signals.
- [x] CVSSv2 `Au` authentication metric now maps into privilege scoring so pre-auth server bugs stay weighted correctly.
- [x] Adjacent (`AV:A`) attack vectors add a partial remote signal when estimating internet exposure.
- [x] Adjusted `management console` regex to avoid mislabelling desktop MMC.
- [x] Added server-side LFI regex feeding domain + exploit scoring.
- [x] Dataset whitelist/blacklist now used to override raw regex signals.
- [x] Vendor key normalization trims corporate suffixes (e.g. "Cisco Systems, Inc.") so curated hints still match.
- [x] Prevented browser entries from re-adding the "Web Applications" tag when only attack context mentions web exploits.


## TODO 

- [ ] **Evaluation suite:** Build hand-labeled CVE test set (edge gateways, MDM, LFI, etc.) and fail CI on regressions. build this in -> use vitests implement somethign where i can easyl generate more testcases by adding more vuln definiton to a json or something
- [x] **Product taxonomy:** Exported normalized curated vendor/product map for reuse.
- [x] **Scoring rules:** Client +2 now requires multiple cues; server weights boosted.
- [x] **NLP hints:** Added admin/API HTTP verb patterns to domain detection logic.
- [x] **Manual review queue:** Flag conflicting signals/overrides as `Mixed/Needs Review`.
- [ ] 4. **Exposure granularity.** Consider turning the boolean `internetExposed` into a multi-level confidence score or separate flags for "likely edge" vs. "needs validation" to reduce false positives on internal-only services.【F:app/utils/classification.ts†L1774-L1822】
