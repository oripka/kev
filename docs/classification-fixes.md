- **Finding summary:** Three recurring failure modes dominate current client/server mistakes: Cisco IOS network device entries are labelled "client" because of an `ios` keyword match, server-side mobile device management products are labelled "client" because of the generic `mobile` keyword, and local file inclusion issues are treated as client execution flaws because of the `local file inclusion` token.

- **What happens:** The classifier treats any occurrence of `ios` as a client-side signal (`\b(?:mobile|android|ios|ipad|iphone|tablet)\b`).【F:app/utils/classification.ts†L936-L954】
- **Impact:** 77 KEV entries reference "IOS" or "IOS XE", all of which are network operating systems. Those records include remote, pre-authentication vulnerabilities (e.g., CVE-2023-20109) that should land on the server-side path.【F:kev.json†L6329-L6339】
- **Why it misfires:** The `ios` token is meant to capture Apple iOS clients but collides with Cisco's network OS terminology. Because the rule contributes +2 points to the client score, it overrides stronger server cues.
- [x] **Suggested fix:** Replace the bare `ios` token with contextual patterns (e.g., `apple ios`, `ipad`, `iphone`, `iOS/iPadOS version`). Add an explicit negative guard for `Cisco IOS`/`IOS XE`/`IOS XR`. Reinforce the server score when the vendor/product strings match network equipment families.


### 2. Mobile device management servers mistaken for client applications
- **What happens:** The same `\bmobile\b` token inside `clientSignalPatterns` fires on MobileIron/EPMM server products because the product name contains the standalone word "Mobile".【F:app/utils/classification.ts†L936-L954】【F:kev.json†L5561-L5573】
- **Impact:** Ivanti Endpoint Manager Mobile (MobileIron Core) and Sentry entries—administrative gateways deployed on the network edge—are treated as client-side exploits even though they are server interfaces.
-  **Why it misfires:** The regex assumes that `mobile` implies an end-user device. In the cached data, `mobile` often appears in the context of server-side mobile device management platforms.
- [x] **Suggested fix:** Require mobile keywords to be coupled with context like `device`, `app`, `application`, or known mobile OS names; or, maintain a curated product override map that tags MobileIron/EPMM as `Networking & VPN` or `Security Appliances` so server hints dominate.


### 3. Local File Inclusion (LFI) rules forcing client classification
- **What happens:** `clientLocalExecutionPatterns` treats `local file inclusion`/`LFI` tokens as proof of a client-side exploit.【F:app/utils/classification.ts†L1040-L1049】
- **Impact:** Server-side vulnerabilities such as CVE-2018-19410 in Paessler PRTG and CVE-2023-2868 in Metabase (both web applications) are pushed into the client-side bucket solely because their descriptions mention "local file inclusion."【F:kev.json†L5559-L5573】【F:kev.json†L3457-L3461】
- **Why it misfires:** LFI is a server-side web exploitation technique; there is no client execution. The pattern currently boosts the client score without any counter-balancing server signal.
- [x] **Suggested fix:** Remove LFI tokens from the client local execution list and instead fold them into server-side web exploit detection (or explicitly tag them under server-side vulnerability categories).

- **`clientSignalPatterns`:** Contains multiple high-impact tokens (`mobile`, `ios`, `local user`) that should be paired with context or vendor/product lookups before increasing the client score.【F:app/utils/classification.ts†L936-L954】
- **`serverSignalPatterns`:** Reliance on generic words like `server`/`service` can still overwhelm legitimate client contexts (e.g., "connects to a server" wording in browser bugs). Introduce negative lookbehinds for phrases such as "malicious server" or couple with network protocol mentions to ensure intent.【F:app/utils/classification.ts†L1060-L1076】
- -[x]**Dataset hints:** Cached data makes it feasible to maintain a whitelist/blacklist per `vendorProject`/`product` pair. Deriving domain hints from that metadata is more stable than raw regex matches.

1. -[x]**Curated product taxonomy:** Build a maintained lookup table mapping normalized vendor/product keys to domain categories (client app, server app, network device, etc.). Use it to seed `domainCategories` before any regex scoring.
2. - [x] **Contextual keyword matching:** For mobile/iOS detection, require composite expressions (e.g., `(apple|ipad|iphone) ios`) and add explicit exclusions (`cisco ios`, `ios xe`, `ios xr`). Apply similar guards to `mobile` (`mobile app`, `mobile device`, `android mobile`).





- [x] Because `/api/fetchKev` enriches entries before they are persisted, these incorrect labels are written directly into `data/cache/*.json`, so every cached dataset and downstream view inherits the error. 【F:server/api/fetchKev.post.ts†L327-L358】【F:server/utils/cache.ts†L22-L105】【F:app/utils/classification.ts†L1581-L1599】

- [x] Catch-all regular expression in `clientApplicationPatterns`
The final pattern in `clientApplicationPatterns` is declared as:
```
/(?:^|[^a-z0-9])(ole(?: compound)?|compound file|cfb|c(om)?)?(?:[^a-z0-9]|$)/i
```
The optional group means the expression can match an empty string between any two word boundaries, so `hasClientApplicationSignal` is set for almost every record. That adds two points to the client score and triggers the tie-breaker that forces a client-side label even when server signals are present. 【F:app/utils/classification.ts†L966-L1001】【F:app/utils/classification.ts†L1424-L1476】
Example: the Jenkins CLI deserialisation issue (`CVE-2017-1000353`) contains no client keywords, yet the faulty regex still fires and the entry is labelled `RCE · Client-side`. 【060fa7†L1-L299】【74e62a†L1-L8】
- [x] Tie-breaking logic favours client indicators
When client and server scores are equal, `determineSide()` returns "Client-side" whenever `hasClientFileSignal` or `hasClientApplicationSignal` is true—even if server keywords, network protocols, and domain hints point to a server. 【F:app/utils/classification.ts†L1473-L1537】
Because the bug above makes `hasClientApplicationSignal` true for the majority of records, this clause overwhelms the rest of the logic and pushes remote services (Cisco ISE APIs, ServiceNow platforms, WebLogic, D-Link NAS management UIs, etc.) into the client bucket. 【060fa7†L1-L299】
- [x] File/attachment heuristics risk additional false positives
Even after fixing the catch-all regex, the `clientFileInteractionPatterns` block can still trip on server-side upload or file-processing vulnerabilities (e.g., dotCMS unrestricted upload, Veeam file API). Those descriptions legitimately mention “uploading malicious files,” but the exploit requires no user action. Without additional guards this will continue to bias results toward the client side. 【F:app/utils/classification.ts†L1004-L1023】

## Recommendations
- [x]**Fix the regex.** Replace the optional group in `clientApplicationPatterns` with a word-boundary anchored expression, e.g. `/\b(?:ole(?:\s+compound)?|compound file|cfb|com)\b/i`, so that it only matches the intended tokens. 【F:app/utils/classification.ts†L966-L1001】
- [x]**Strengthen the tie-breaker.** `determineSide()` now prefers server classifications whenever server protocols, domain hints, or signals stand alongside matching client cues, only returning "Client-side" when the client score is strictly higher or server evidence is absent.【F:app/utils/classification.ts†L1582-L1618】
- [x]**Narrow file heuristics.** Add guards to `clientFileInteractionPatterns` to require explicit user-action verbs (“when opening”, “double-click”) before scoring client points, and ignore matches that coexist with server keywords (“upload”, “API request”). 【F:app/utils/classification.ts†L1004-L1023】

## Toward a bulletproof classifier

- [x]**Feature weighting:** Treat domain categories and network protocol mentions as hard constraints; only downgrade to client-side when both context and CVSS vectors confirm local interaction. 【F:app/utils/classification.ts†L1403-L1476】


---

## Misclassification Drivers

### 1. Optional OLE/CFB pattern flags everything as a client artifact
- [x] The `clientApplicationPatterns` array includes `/([^a-z0-9])(ole(?: compound)?|compound file|cfb|c(om)?)?([^a-z0-9])/`, where the inner group is optional. Because the keyword group can be empty, the pattern matches any non-alphanumeric boundary and sets `hasClientApplicationSignal` to `true` for nearly every entry.【F:app/utils/classification.ts†L990-L1002】 Debug output confirms that server-side vulnerabilities such as DELMIA Apriso and FreePBX pick up `hasClientApplicationSignal: true` purely because of this regex, even though no client artifact is mentioned.【26c978†L1-L64】
- Those entries are therefore emitted as client-side RCE despite living in server or edge domains.【6e04f7†L1-L29】 Example source data lines make clear that both vulnerabilities target remote APIs or administrative portals rather than local clients.【F:kev.json†L414-L423】【F:kev.json†L532-L541】

- [x] Replace the optional group with explicit tokens (e.g., `/\b(?:ole(?: compound)?|compound file|cfb)\b/`) and gate it behind nearby verbs such as "open" or "load". Add regression fixtures so that server-focused records like CVE-2025-5086 and CVE-2025-57819 must classify as server-side before merges.


- [x]The client signal list treats any occurrence of `mobile`, `android`, `ios`, or `tablet` as a client-side hint.【F:app/utils/classification.ts†L936-L953】 That works for browser exploits, but server products such as Ivanti Endpoint Manager Mobile (an MDM server) contain "Mobile" in the product name.
- Classification output shows every EPMM vulnerability landing in the client-side RCE bucket even though the domain classifier correctly tags them as Web Applications and Internet Edge services.【6e04f7†L18-L25】 The KEV source text emphasizes remote API abuse against the management server rather than an end-user client.【F:kev.json†L1427-L1438】

- [x] Only treat `mobile` (and related tokens) as client hints when the domain categories include Browsers or when nearby text references actions like "user opens" or "device owner". Otherwise, treat `mobile` inside server/edge domains as neutral or even as a server hint for MDM platforms.

### 3. Local File Inclusion mapped to client execution
- [x] Resolved by routing LFI tokens through `serverSignalPatterns` and clearing the client local-execution flag whenever those keywords appear, preventing server-side LFI cases from being mis-labelled as client exploits.【F:app/utils/classification.ts†L1429-L1452】
- Paessler PRTG’s LFI entry, for example, previously landed in the client bucket; re-run the evaluation dataset to confirm the new guard now emits server-side exploit layers for those CVEs.【6e04f7†L26-L33】【F:kev.json†L2756-L2765】

- [ ]**Recommendation.** Move the LFI tokens into a dedicated server-side indicator list (or at minimum remove them from the client list) and add tests that ensure LFI CVEs reach a server-side exploit layer.

## Toward a bullet-proof classification pipeline
- [ ] Build a curated evaluation set of high-signal CVEs (edge gateways, MDM, collaboration suites, document readers, LFI cases) with hand-labeled exploit layers. Run the classifier against this set on every change and fail the build when any regression appears.

- [ ]Add guardrails around regex additions: require explicit context windows or paired verbs, and run new patterns against the cached catalog to surface large-scale label shifts before merging.
r.


- -[x]**Augment feature extraction.** Consider layering lightweight NLP (keyword lists for “API endpoint”, “admin portal”, HTTP verbs) and CVSS hints (e.g., treat AV:N + PR:N as strong server evidence) to supplement regex matching and further separate client from server contexts.【F:app/utils/classification.ts†L1176-L1314】【F:app/utils/classification.ts†L1382-L1474】

2.- [x] **Rebalance scoring weights.** Gate the +2 client bonus on combined evidence (e.g., require both a client application match and a file/interaction cue) and add similar weight for `domainSuggestsServer` or explicit server signals so network appliances cannot be overridden by a stray client pattern.【F:app/utils/classification.ts†L1410-L1476】


- [ ]**Consider confidence thresholds and overrides.** When both client and server signals fire, emit dual labels (or flag as “Mixed/Needs review”) instead of forcing a tie-break, and allow manual overrides for high-value appliances until the heuristics mature. -> add a dedicated label for that so we can easily fitler and find out how to classify them better


- [x] **Narrow file heuristics.** Add guards to `clientFileInteractionPatterns` to require explicit user-action verbs (“when opening”, “double-click”) before scoring client points, and ignore matches that coexist with server keywords (“upload”, “API request”). 【F:app/utils/classification.ts†L1004-L1023】

- [x] The server regex `/management (?:server|interface|console)/` treats "management console"
  as server infrastructure, tipping the server score past the client score once combined
  with generic remote-context cues.【F:kev.json†L3782-L3794】【bb1e2b†L7-L9】【de87f7†L1-L12】【F:app/utils/classification.ts†L1060-L1075】


### Windows Management Console (CVE-2024-43572)

*Expected*: Client-side OS vulnerability (Windows MMC) that executes with user context.

*Observed*: Labeled `RCE · Server-side Non-memory` because two signals fire simultaneously:
- [x]`/\b(?:management (?:server|interface|console))\b/i`** – this server signal is too broad.
  It forces Windows MMC, browser settings panes, and other desktop consoles into server
  territory.【F:app/utils/classification.ts†L1060-L1075】【de87f7†L1-L12】
- [ ] **Add non-RCE exploit layer buckets.** Introduce classifications such as "Auth Bypass ·
   Edge" or "Configuration Abuse" so the catalog captures high-severity API failures instead
   of returning empty arrays.【6a6ebe†L3-L16】




# evaluate why this is categoirze as non.memory  it can be ewither memory coruption or not not both!!!

- [ ] fix tagging stuff both a smemory corruption and non-emmorcoruption
Microsoft SMBv1 Remote Code Execution Vulnerability

CVE-2017-0144
CISA KEV
ENISA
Historic dataset
Metasploit
Description

ETERNALBLUE / DOUBLEPULSAR
The SMBv1 server in multiple Microsoft Windows versions allows remote attackers to execute arbitrary code via crafted packets.
Vendor

Microsoft
Product

Windows
Date added

2017-01-01T00:00:00.000Z
Ransomware use

Known

CVSS

High 8.8
v3.1
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

EPSS

94.3%
Assigner

microsoft

Exploit activity

Timeline of key milestones

Follow how this CVE moved from publication to active exploitation across monitored feeds.

7 events
3214 days from first to latest milestone
Jan 1, 2017
2 events recorded
• CVE published — Published by microsoft. · Source: NVD

• Historic exploitation noted — Captured in the historic exploited vulnerability archive. · Source: Historic dataset
—
72 days later
No tracked activity was recorded during this gap.
Mar 14, 2017
Metasploit entry published
Module path: exploits/windows/smb/ms17_010_eternalblue · Source: Metasploit
—
31 days later
No tracked activity was recorded during this gap.
Apr 14, 2017
Metasploit entry published
Module path: exploits/windows/smb/smb_doublepulsar_rce · Source: Metasploit
—
4 years 303 days later
No tracked activity was recorded during this gap.
Feb 10, 2022
Listed by ENISA
ENISA highlighted this CVE as actively exploited in the Threat Landscape for exploited vulnerabilities. · Source: ENISA
Feb 10, 2022
Flagged in CISA KEV
CISA confirmed active exploitation and added the CVE to the Known Exploited Vulnerabilities catalog. · Source: CISA KEV
—
3 years 253 days later
No tracked activity was recorded during this gap.
Oct 20, 2025
Last updated
Most recent catalog update recorded for this entry.
Source

View advisory
Domain categories

Non-Web Applications
Exploit profiles

RCE · Server-side Non-memory
RCE · Server-side Memory Corruption
DoS · Server-side
Vulnerability categories

Remote Code Execution
Memory Corruption
Denial of Service
References

https://packetstormsecurity.com/files/cve/CVE-2017-0144
https://www.exploit-db.com/exploits/42031/