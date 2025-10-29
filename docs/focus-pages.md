# Focus Pages for Critical Vulnerability Themes

This document proposes a set of curated "focus pages" that translate raw vulnerability data into high-impact narratives. Each page is scoped to one topical risk area so incident responders can immediately understand why it matters, how frequently it is exploited, and what they should do next.

## Shared Design Principles

- **Single-topic storytelling:** Dedicate the entire page to a tightly scoped risk theme so context switching is minimized.
- **Evidence-first visuals:** Lead with hard numbers (counts, trends, attack surface) pulled from CISA KEV, ENSISA, and the custom historical lists.
- **Actionable framing:** Couple every insight with concrete remediation guidance and patches or mitigations that are proven to work.
- **Exploitability cues:** Highlight whether public exploits or Metasploit modules exist, plus the median time-to-exploit after disclosure.
- **Patch feasibility:** Reassure operators by showing change-control impact (e.g., availability of vendor fixes, reboot requirements).
- **Linkable filters:** Provide deep links into the catalog view with the filters that reproduce the data underpinning each callout.

## Page Concepts

### 1. Edge Device Exposure: RDP/SMB & Perimeter Services

**Goal:** Explain why externally exposed services (RDP, SMB, VPN appliances) consistently lead to catastrophic breaches.

| Section | What to Show | Why it Matters |
| --- | --- | --- |
| Exploit Frequency Snapshot | "How often did this type of service show up in KEV in the last 5 years?" Use a heat map keyed by protocol (RDP/SMB, SSH, HTTP, proprietary VPN). | Demonstrates sustained attacker interest and rapid re-use of exploits. |
| Time-to-Exploit Funnel | Timeline from CVE publication → exploit observed → patch available. | Highlights that defenders typically have <10 days before exploitation ramps up. |
| Patchability Matrix | Columns for Vendor firmware, OS images, and third-party appliances with patch difficulty (simple reboot vs. service window). | Helps operators triage based on upgrade complexity. |
| Real-world Incidents | Curated list of two high-profile breaches tied to each protocol. | Reinforces the stakes beyond abstract metrics. |
| Catalog Shortcuts | Buttons that open the catalog filtered by `service: RDP`, `exposed: true`, etc. | Lets the reader pivot directly into the data to build patch queues. |

### 2. Web Application Injection & Supply-Chain Weak Points

**Goal:** Communicate why web app vulnerabilities (RCE, SQLi, command injection) deserve immediate patch attention despite appearing "just web".

| Section | What to Show | Why it Matters |
| --- | --- | --- |
| Attack Surface Overview | Stacked bar showing share of KEV entries mapped to web stacks (CMS, CI/CD portals, API gateways). | Visual proof that web apps dominate exploited CVEs. |
| Known Exploit Availability | Badge grid indicating whether public PoCs, Metasploit modules, or botnet campaigns exist (`yes / partial / none`). | Shows defenders which issues are being actively commoditized. |
| Exploitation Chain Example | Step-by-step story of a supply-chain compromise (e.g., build server command injection leading to downstream malware). | Makes the risk tangible for non-web specialists. |
| Mitigation Playbook | Checklist of immediate actions (WAF rules, secrets rotation, package pinning) and long-term fixes. | Provides clear next steps instead of generic "patch now". |
| Business Impact Lens | Quick stats on downtime costs and data exposure from recent incidents. | Connects technical risk to business outcomes for leadership briefings. |

### 3. Email & Collaboration Attack Corridors

**Goal:** Highlight why mail servers and collaboration suites remain prime targets for initial access.

| Section | What to Show | Why it Matters |
| --- | --- | --- |
| Exploit Cadence | Rolling 12-month line chart comparing Exchange/Outlook vs. other mail platforms in KEV. | Illustrates recurrent waves of mail exploit campaigns. |
| External Exposure Risk | Gauge of how many vulnerable instances are typically internet-facing (use Shodan-derived telemetry if available). | Reinforces urgency for perimeter hardening. |
| Patch Adoption Lag | Median days between patch release and observed adoption from telemetry or user-submitted data. | Makes the "easy to patch?" question concrete. |
| Recommended Response Ladder | Phased response (disable vulnerable endpoint, apply vendor patch, run compromise assessment). | Guides SOC and IT teams through prioritized actions. |
| Incident Library | Links to notable CVEs with short summaries and references. | Supports proactive tabletop exercises. |

## Interaction Model

1. **Entry Points:** Surface the focus pages from the homepage as featured cards ("Top Critical Themes This Quarter") or from a "Focus" tab.
2. **Data Integration:** Each metric references the same normalized tables powering the catalog, ensuring consistency. Whenever possible, pre-compute aggregates to keep page loads fast.
3. **Narrative Blocks:** Combine textual insights, iconography, and charts. Use Nuxt UI `Card` and `Statistic` components to keep styling consistent with the rest of the app.
4. **Call-to-Action:** Finish each page with an "Add to Patch Queue" button that pulls matching CVEs into a saved filter for follow-up.

## Implementation Notes

- Create dedicated routes, e.g., `/focus/edge-services`, `/focus/web-injection`, `/focus/collaboration`.
- Back the pages with lightweight server endpoints that return pre-aggregated metrics and curated incident writeups.
- Leverage the existing badge filters so one click can reproduce the dataset shown (e.g., `?vector=network&category=edge-service`).
- Store editorial copy and incident blurbs in Markdown to keep updates simple and reviewable.
- Schedule a quarterly content review to refresh incidents, metrics, and guidance so the pages stay current.

By combining evidence, storytelling, and direct links to remediation workflows, these focus pages help teams immediately identify which vulnerabilities demand urgent attention and why.
