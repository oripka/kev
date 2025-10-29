# Critical Focus Page Concepts

## Purpose

Create dedicated dashboard pages that highlight high-risk vulnerability themes so remediation teams immediately understand why a
category matters, which assets are exposed, and what to do next. Each page mixes narrative context, curated metrics, and
pre-filtered vulnerability lists so the insight is immediately actionable.

The sample matrix from the ideation session (``Webserver``/``OS``/``Mail``/``Webapp`` vs. exploit availability, exposure frequency,
"can we patch?", etc.) inspires the data slices and messaging used below.

## Design Principles

1. **Single-topic immersion** – each page focuses on one exploit vector or asset class, using language that resonates with the
   engineers who own that surface area.
2. **Explain the "why" before the "what"** – open with a concise narrative, ideally referencing recent incidents or threat actor
   activity.
3. **Quantify exposure using the KEV dataset** – lean on the ``how often``, ``public exploit``, and ``patchable`` dimensions from the
   table to frame urgency.
4. **Map to remediation playbooks** – each page ends with immediate actions, policy guardrails, and who should own the fix.

## Page Blueprint

Each topic page shares a consistent scaffold so users build intuition quickly:

- **Hero section** with a short headline ("Why Web Application 0-days Dominate Incident Response") and a supporting paragraph that
  restates the risk in plain language.
- **Key signal cards** derived from the matrix metrics. Examples:
  - "Exploit releases in last 5 years" → show the median time-to-public-exploit for this surface vs. others.
  - "Patch coverage" → highlight the percentage of entries marked "ja" vs. "nein" in the "Can we patch?" column.
  - "Internet exposure" → track how many entries map to externally reachable services (``Webapp`` column at 400 stands out).
- **Narrative strip** that ties the numbers to real-world impact, e.g., breach case studies, ransomware trends, or regulatory fines.
- **Interactive filters** pre-loaded with relevant tags (service type, exploit technique, product family) so the vulnerability list
  below instantly reflects the topic at hand.
- **Action panel** listing remediation steps, owners, and links to runbooks.

## Topic Examples

### 1. Web Application Zero-Days

- **Why it matters**: The ``Webapp`` column shows ~400 exploited entries with frequent 0-day-to-exploit conversions. Attackers leverage
  public proof-of-concept code to pivot from initial access to data exfiltration within hours.
- **Metrics to highlight**:
  - ``How often was there a 0-day?`` → visual timeline of web app CVEs with 0-day exploitations vs. other categories.
  - ``Is a public exploit available?`` → callout showing "ja" for nearly every severe entry, indicating easily weaponized payloads.
  - ``Can we patch easily?`` → emphasize the uncertainty ("???" in the table) and guide teams toward virtual patching/WAF rules when
    vendor fixes lag.
- **Action guidance**:
  - Prioritize WAF virtual patching and credential rotation runbooks.
  - Trigger dependency scanning for libraries tied to the flagged CVEs.
  - Tag owners in the app security backlog with high/medium/low urgency badges.

### 2. Edge & Gateway Devices (RDP/SMB, VPNs, Routers)

- **Why it matters**: External services (``RDP/SMB`` column) should never be internet-facing, yet the table suggests lingering
  exposure. These devices often lag in patch adoption and enable lateral movement immediately after compromise.
- **Metrics to highlight**:
  - ``Is the service exposed externally?`` → show the count of entries where TCP/IP services were reachable from the internet at time
    of exploitation.
  - ``Time to patch`` → compare vendor release vs. exploitation to quantify how long systems remained vulnerable.
  - ``Credential reuse impact`` → overlay stats about brute-force exploitation post-patch.
- **Action guidance**:
  - Enforce network segmentation and conditional access baselines.
  - Surface automation scripts for firmware updates and configuration backups.
  - Provide checklist for emergency isolation of compromised gateways.

### 3. Mail Infrastructure Exploits

- **Why it matters**: The mail column sits around "1-3" exploited cases but each had direct impact on business continuity (e.g.,
  Exchange ProxyShell). Public exploits ("ja") mean defenders must assume compromise once vulnerability is announced.
- **Metrics to highlight**:
  - ``Blast radius`` → chart the number of organizations affected vs. time to remediation.
  - ``Patch friction`` → detail common blockers (hybrid deployments, change freezes) and pair them with mitigation scripts.
  - ``Detection coverage`` → show telemetry gaps when exploitation happens before patch windows.
- **Action guidance**:
  - Link to rapid hardening guides (disabling legacy auth, tightening EWS/OWA exposure).
  - Provide script snippets to detect webshells or suspicious child processes.
  - Encourage tabletop exercises for mail outage response.

### 4. Operating System Privilege Escalation

- **Why it matters**: Privilege-escalation CVEs in the ``OS`` column show "~1-3" 0-days annually with mixed patch availability. These
  enable ransomware operators to elevate quickly once they gain an initial foothold.
- **Metrics to highlight**:
  - ``Patch adoption lag`` → measure how long endpoints stay unpatched after vendor release.
  - ``Exploit availability`` → scoreboard of open-source exploits ("ja/nein") to aid SOC threat hunting.
  - ``Attack chain dependency`` → illustrate how OS privilege escalation completes the kill chain started by phishing or web exploits.
- **Action guidance**:
  - Promote attack surface reduction rules and application control policies.
  - Share EDR detection rules for known exploit primitives.
  - Provide automation flows for accelerated patch deployment (Intune, Ansible, etc.).

## Implementation Notes

- **Data wiring**: Each page should use saved filter presets (service type, exploit technique, vendor categories) so users can share
  URLs. When the preset is loaded, the catalog view already reflects the filtered vulnerabilities.
- **Content management**: Store the narrative copy and action checklists in Markdown or CMS entries so security analysts can refresh
  them without code deployments.
- **Visualization**: Reuse existing chart components (bar, timeline, gauge) but configure them with topic-specific datasets sourced
  from the KEV feed and historical exploit timelines.
- **Call-to-action widgets**: Add buttons for "Export list" and "Send to ticketing" to accelerate remediation workflows.

Delivering these curated pages turns raw KEV entries into focused situational awareness, helping teams patch the exposures that
matter most.
