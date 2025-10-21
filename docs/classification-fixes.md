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


## TODO 

- [ ] **Evaluation suite:** Build hand-labeled CVE test set (edge gateways, MDM, LFI, etc.) and fail CI on regressions. build this in -> use vitests implement somethign where i can easyl generate more testcases by adding more vuln definiton to a json or something
- [ ] **Product taxonomy:** Finalize and publish normalized vendor/product → domain mapping.  
- [ ] **Scoring rules:** Lock +2 client bonus behind combined cues; boost domain/server weights.  
- [ ] **NLP hints:** Add lightweight layer (API/admin terms, HTTP verbs, CVSS AV/PR).  
- [ ] **Manual review queue:** Populate `Mixed / Needs Review` entries for human verification.  