import type { FocusMetricKey } from "~/utils/focusMetrics";

export type FocusTopicCategory = "critical" | "theme";

export type FocusNarrative = {
  title: string;
  body: string;
};

export type FocusActionLink = {
  label: string;
  href: string;
};

export type FocusAction = {
  title: string;
  description: string;
  owner?: string;
  links?: FocusActionLink[];
};

export type FocusShortcut = {
  label: string;
  description?: string;
  query: Record<string, string | number | boolean>;
};

export type FocusIncident = {
  title: string;
  summary: string;
  url?: string;
};

export type FocusMetricDefinition = {
  key: FocusMetricKey;
  label: string;
  description: string;
};

export type FocusTopic = {
  slug: string;
  category: FocusTopicCategory;
  title: string;
  headline: string;
  summary: string;
  hero: {
    kicker?: string;
    description: string;
  };
  filters: Record<string, string | number | boolean>;
  metrics: FocusMetricDefinition[];
  narratives: FocusNarrative[];
  actions: FocusAction[];
  shortcuts: FocusShortcut[];
  incidents: FocusIncident[];
  highlightNotes?: string[];
  keySignalNotes?: string[];
  timelinePeriod?: "monthly" | "weekly" | "daily";
  recommendedOwners?: string[];
  additionalInsights?: string[];
};

const defaultSources = "kev,enisa,historic,metasploit,poc";

export const focusTopics: FocusTopic[] = [
  {
    slug: "web-application-zero-days",
    category: "critical",
    title: "Web Application Zero-Days",
    headline: "Why web application 0-days dominate incident response",
    summary:
      "Frequent zero-day-to-exploit conversions across customer portals, CI/CD pipelines, and SaaS integrations make web applications the most volatile surface in the KEV backlog.",
    hero: {
      kicker: "Critical focus",
      description:
        "Attack crews turn fresh advisories into weaponised payloads within hours. This page summarises how often web applications are compromised before patches land and which remediation levers buy back time.",
    },
    filters: {
      domain: "Web Applications",
      publicExploitOnly: true,
      sources: defaultSources,
    },
    metrics: [
      {
        key: "fiveYearMatchCount",
        label: "Exploit releases in the last five years",
        description:
          "How many KEV listings for web applications have been observed since the start of the five-year window.",
      },
      {
        key: "pocWithin30DaysShare",
        label: "0-day conversion window",
        description:
          "Share of entries where public exploit material appeared within 30 days of disclosure, signalling immediate weaponisation.",
      },
      {
        key: "publicExploitShare",
        label: "Public exploit availability",
        description:
          "Percentage of records backed by PoC repositories or Metasploit modules, highlighting commoditised payloads.",
      },
      {
        key: "dueDateCoverageShare",
        label: "Patch guidance coverage",
        description:
          "Portion of entries where vendors supplied due dates or remediation instructions defenders can action right away.",
      },
    ],
    narratives: [
      {
        title: "Rapid commoditisation",
        body:
          "Proof-of-concept code frequently ships in the same window as the advisory. Ransomware and data-theft crews reuse those payloads across CMS platforms, build servers, and external APIs with almost no adaptation.",
      },
      {
        title: "Operational impact",
        body:
          "Application and platform teams must coordinate WAF updates, dependency upgrades, and credential resets under extreme time pressure. Highlight the CVEs in this list during weekly incident readiness stand-ups.",
      },
    ],
    actions: [
      {
        title: "Deploy virtual patching",
        description:
          "Roll out WAF or reverse-proxy signatures that block the exploit parameters referenced in these CVEs until vendor binaries are installed.",
        owner: "Application security",
      },
      {
        title: "Audit third-party dependencies",
        description:
          "Trigger software composition analysis on repositories mapped to the affected CVEs and fast-track dependency upgrades in CI/CD pipelines.",
        owner: "DevSecOps",
      },
      {
        title: "Stage credential hygiene drills",
        description:
          "Coordinate with identity engineering to rotate shared secrets, service accounts, and session stores touched by exposed applications.",
        owner: "Identity engineering",
      },
    ],
    shortcuts: [
      {
        label: "RCE web stacks",
        description: "Remote code execution entries across public-facing web services.",
        query: {
          domain: "Web Applications",
          vulnerability: "Remote Code Execution",
        },
      },
      {
        label: "Command injection",
        description: "Focus on supply-chain style command injection flaws.",
        query: {
          domain: "Web Applications",
          vulnerability: "Command Injection",
        },
      },
      {
        label: "Known PoCs only",
        description: "Keep results with public proof-of-concept or Metasploit coverage.",
        query: {
          domain: "Web Applications",
          publicExploitOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "MOVEit Transfer SQL injection",
        summary:
          "CVE-2023-34362 moved from disclosure to mass exploitation in hours, allowing data theft from managed file transfer portals.",
      },
      {
        title: "Confluence OGNL zero-days",
        summary:
          "Multiple Atlassian Confluence RCE flaws (e.g. CVE-2022-26134) were weaponised immediately for ransomware staging and crypto-mining.",
      },
    ],
    highlightNotes: [
      "Web applications account for the highest concentration of actively exploited CVEs in the dataset.",
      "Attackers reuse PoC payloads to pivot from initial access to data exfiltration within hours of disclosure.",
    ],
    keySignalNotes: [
      "Use the timeline to compare web application exploit spikes against other domains when briefing leadership.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Application security", "Platform engineering"],
  },
  {
    slug: "edge-gateway-devices",
    category: "critical",
    title: "Edge & Gateway Devices",
    headline: "When perimeter services stay exposed, compromise is immediate",
    summary:
      "Remote access gateways, VPN appliances, and legacy RDP/SMB endpoints continue to surface in KEV with startling regularity, and nearly all are reachable from the internet when exploited.",
    hero: {
      kicker: "Critical focus",
      description:
        "Edge systems accumulate configuration drift and slow firmware cycles. This view quantifies how quickly adversaries weaponise them and why they remain a favoured launchpad for lateral movement.",
    },
    filters: {
      domain: "Internet Edge",
      internetExposedOnly: true,
      sources: defaultSources,
    },
    metrics: [
      {
        key: "fiveYearMatchCount",
        label: "Documented edge exploits in five years",
        description:
          "Number of KEV entries tied to internet-facing edge services since the five-year cut-off.",
      },
      {
        key: "medianExploitWindowDays",
        label: "Median time-to-exploit",
        description:
          "Median number of days between public disclosure and KEV listing, underscoring short defender response windows.",
      },
      {
        key: "internetExposedShare",
        label: "Externally reachable services",
        description:
          "Share of records explicitly flagged as internet exposed at time of exploitation.",
      },
      {
        key: "ransomwareShare",
        label: "Ransomware association",
        description:
          "Portion of entries linked to known ransomware activity after exploitation.",
      },
    ],
    narratives: [
      {
        title: "Exposure remains stubborn",
        body:
          "Despite repeated incidents, RDP, SMB, and VPN services still appear on public attack surfaces. The telemetry here helps network teams prioritise aggressive segmentation and conditional access baselines.",
      },
      {
        title: "Patching is rarely immediate",
        body:
          "Vendors often require full firmware upgrades or maintenance windows, stretching remediation timelines and leaving gaps for credential stuffing or brute-force follow-on attacks.",
      },
    ],
    actions: [
      {
        title: "Harden perimeter policy",
        description:
          "Enforce network segmentation, conditional access, and MFA for any edge system that cannot be fully isolated.",
        owner: "Network engineering",
      },
      {
        title: "Automate firmware updates",
        description:
          "Adopt scripted upgrade pipelines and configuration backups so edge devices can be patched on cadence without outages.",
        owner: "Infrastructure operations",
      },
      {
        title: "Isolate compromised gateways fast",
        description:
          "Maintain emergency runbooks for revoking certificates, rotating credentials, and redirecting traffic away from suspect appliances.",
        owner: "Incident response",
      },
    ],
    shortcuts: [
      {
        label: "RDP and SMB",
        description: "Focus on remote desktop and file sharing exposures.",
        query: {
          domain: "Internet Edge",
          exploit: "Auth Bypass · Edge",
        },
      },
      {
        label: "VPN appliances",
        description: "Filter to authentication bypass issues targeting VPN gateways.",
        query: {
          domain: "Internet Edge",
          vulnerability: "Authentication Bypass",
        },
      },
      {
        label: "Known ransomware",
        description: "Gateway exploits that show up in ransomware tradecraft.",
        query: {
          domain: "Internet Edge",
          ransomwareOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "Pulse Secure VPN compromises",
        summary:
          "Pulse Secure and Ivanti Connect Secure vulnerabilities continue to enable credential theft and ransomware ingress.",
      },
      {
        title: "Citrix Bleed (CVE-2023-4966)",
        summary:
          "Citrix ADC and Gateway session hijacking drove widespread lateral movement campaigns within days of disclosure.",
      },
    ],
    highlightNotes: [
      "Edge services typically remain exploitable for weeks because maintenance windows and firmware approvals lag.",
      "Credential reuse and session hijacking frequently follow successful exploitation.",
    ],
    keySignalNotes: [
      "Use the ransomware share metric to show how quickly these footholds lead to business-impacting incidents.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Network engineering", "Security operations"],
  },
  {
    slug: "mail-infrastructure",
    category: "critical",
    title: "Mail Infrastructure Exploits",
    headline: "Mail outages escalate quickly when exploitation predates patch windows",
    summary:
      "Mail gateways and collaboration suites carry comparatively few KEV entries, yet each one produces outsized operational disruption and follow-on compromise.",
    hero: {
      kicker: "Critical focus",
      description:
        "Exchange, Outlook, and hybrid mail stacks sit at the intersection of identity and data exfiltration. This page surfaces how frequently they are targeted and why defenders must assume compromise once disclosures land.",
    },
    filters: {
      domain: "Mail Servers",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "rolling12MonthCount",
        label: "Exploit cadence",
        description:
          "Rolling 12-month total of mail-related KEV entries to visualise recurring campaign waves.",
      },
      {
        key: "internetExposedShare",
        label: "Internet exposure",
        description:
          "Share of entries involving internet-facing services at time of exploitation.",
      },
      {
        key: "dueDateCoverageShare",
        label: "Patch guidance present",
        description:
          "Portion of entries with clear remediation deadlines or vendor scripts.",
      },
      {
        key: "ransomwareShare",
        label: "Ransomware linkage",
        description:
          "Percentage of entries referencing known ransomware or criminal follow-on activity.",
      },
    ],
    narratives: [
      {
        title: "Business continuity risk",
        body:
          "Every mail outage lands in executive escalations. Track these KEV entries to align change windows and prepare customer communications ahead of public exploitation.",
      },
      {
        title: "Detection coverage",
        body:
          "Hunt for webshells, suspicious child processes, and credential export immediately after applying patches or mitigations.",
      },
    ],
    actions: [
      {
        title: "Harden perimeter access",
        description:
          "Disable legacy authentication, tighten external access to Outlook Web App, and enforce conditional access on remote protocols.",
        owner: "Messaging engineering",
      },
      {
        title: "Automate compromise assessment",
        description:
          "Deploy scripts to scan for known mail exploitation artefacts and collect forensic triage packages.",
        owner: "Security operations",
      },
      {
        title: "Plan outage playbooks",
        description:
          "Run tabletop exercises that simulate extended mail downtime and data exfiltration scenarios.",
        owner: "Business continuity",
      },
    ],
    shortcuts: [
      {
        label: "Exchange online",
        description: "Microsoft Exchange and Outlook related CVEs.",
        query: {
          domain: "Mail Servers",
          vendor: "microsoft",
        },
      },
      {
        label: "Hybrid deployments",
        description: "Focus on vendors with on-prem and cloud hybrid mail footprints.",
        query: {
          domain: "Mail Servers",
          publicExploitOnly: true,
        },
      },
      {
        label: "Credential theft",
        description: "Entries associated with credential harvesting.",
        query: {
          domain: "Mail Servers",
          vulnerability: "Authentication Bypass",
        },
      },
    ],
    incidents: [
      {
        title: "ProxyShell campaign",
        summary:
          "Exchange ProxyShell chained exploits (2021) caused persistent webshell deployments and widespread business disruption.",
      },
      {
        title: "Storm-0558 Outlook token theft",
        summary:
          "OAuth token forging exploited Outlook Web Access to exfiltrate sensitive mail from targeted tenants.",
      },
    ],
    highlightNotes: [
      "Even low-frequency mail CVEs demand immediate response because impact spans messaging, identity, and compliance.",
    ],
    keySignalNotes: [
      "Pair the cadence metric with outage impact narratives during leadership briefings.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Messaging engineering", "Security operations"],
  },
  {
    slug: "os-privilege-escalation",
    category: "critical",
    title: "Operating System Privilege Escalation",
    headline: "Privilege escalation closes the loop on every intrusion chain",
    summary:
      "Once initial access is achieved, operating system escalation flaws give adversaries the keys to deploy ransomware or exfiltrate data within minutes.",
    hero: {
      kicker: "Critical focus",
      description:
        "These CVEs illustrate how quickly attackers can move from foothold to full compromise. Quantify the patch lag and exploit availability to unlock faster endpoint response.",
    },
    filters: {
      domain: "Operating Systems",
      exploit: "Privilege Escalation",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "fiveYearMatchCount",
        label: "Privilege escalation in five years",
        description:
          "Total KEV entries for operating system privilege escalation recorded since the five-year lookback.",
      },
      {
        key: "medianPatchWindowDays",
        label: "Median patch adoption window",
        description:
          "Median number of days between KEV listing and due dates, indicating how long systems stay exposed.",
      },
      {
        key: "publicExploitShare",
        label: "Exploit availability",
        description:
          "Share of entries with public exploit tooling to aid threat hunting and validation.",
      },
      {
        key: "ransomwareShare",
        label: "Ransomware correlation",
        description:
          "Portion of entries that adversaries weaponised in ransomware campaigns after gaining local access.",
      },
    ],
    narratives: [
      {
        title: "Endpoint hardening is decisive",
        body:
          "Attacker dwell time collapses when privilege escalation bugs stay unpatched. Map these CVEs into attack surface reduction and application control policies.",
      },
      {
        title: "Threat hunting fuel",
        body:
          "Open-source exploit proofs let defenders replicate behaviour and tune EDR detection logic before an incident hits production.",
      },
    ],
    actions: [
      {
        title: "Accelerate endpoint patching",
        description:
          "Use Intune, Ansible, or configuration management pipelines to push patches within defined SLOs for escalations.",
        owner: "Endpoint engineering",
      },
      {
        title: "Deploy attack surface reduction",
        description:
          "Implement ASR rules, kernel protections, and application control policies that blunt escalation techniques.",
        owner: "Endpoint security",
      },
      {
        title: "Publish detection rules",
        description:
          "Share EDR detection analytics tuned to the exploit primitives outlined in each CVE.",
        owner: "Threat detection",
      },
    ],
    shortcuts: [
      {
        label: "Kernel-level bugs",
        description: "Privilege escalation CVEs that touch kernel components.",
        query: {
          domain: "Operating Systems",
          exploit: "Privilege Escalation",
        },
      },
      {
        label: "Known ransomware",
        description: "Entries tied to ransomware playbooks.",
        query: {
          domain: "Operating Systems",
          ransomwareOnly: true,
        },
      },
      {
        label: "High severity",
        description: "Filter for high or critical CVSS scores.",
        query: {
          domain: "Operating Systems",
          cvssMin: 7,
        },
      },
    ],
    incidents: [
      {
        title: "PrintNightmare",
        summary:
          "CVE-2021-34527 enabled remote-to-local escalation, fuelling ransomware deployment across unmanaged endpoints.",
      },
      {
        title: "Dirty Pipe",
        summary:
          "CVE-2022-0847 granted near-instant root on Linux systems, showing how attackers chain privilege escalation after web exploits.",
      },
    ],
    highlightNotes: [
      "Privilege escalation flaws turn initial footholds into domain dominance.",
    ],
    keySignalNotes: [
      "Compare median patch windows against your internal SLA to spot gaps.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Endpoint engineering", "Threat detection"],
  },
  {
    slug: "edge-device-exposure",
    category: "theme",
    title: "Edge Device Exposure",
    headline: "Perimeter services demand continuous patch orchestration",
    summary:
      "Summarise why externally exposed protocols such as RDP, SMB, SSH, and VPN endpoints show up year after year in KEV and how quickly defenders must act.",
    hero: {
      kicker: "Focus page",
      description:
        "Security, networking, and infrastructure teams can reuse these metrics to brief leadership on the urgency behind edge hardening.",
    },
    filters: {
      domain: "Internet Edge",
      internetExposedOnly: true,
      sources: defaultSources,
    },
    metrics: [
      {
        key: "rolling12MonthCount",
        label: "12-month exploit frequency",
        description:
          "Rolling total of edge-service CVEs observed in KEV over the last year.",
      },
      {
        key: "medianExploitWindowDays",
        label: "Time-to-exploit funnel",
        description:
          "Median difference between public disclosure and KEV listing for edge services.",
      },
      {
        key: "medianPatchWindowDays",
        label: "Patchability window",
        description:
          "Median span between KEV listing and remediation due dates for edge devices.",
      },
      {
        key: "internetExposedShare",
        label: "Externally reachable proportion",
        description:
          "Percentage of entries explicitly marked as internet exposed.",
      },
    ],
    narratives: [
      {
        title: "Why it matters",
        body:
          "Each public-facing protocol gives adversaries a reusable foothold. Show this page to justify aggressive decommissioning and migration plans.",
      },
    ],
    actions: [
      {
        title: "Create segmentation guardrails",
        description:
          "Inventory exposed services, move them behind VPN or ZTNA brokers, and enforce conditional access.",
        owner: "Network engineering",
      },
      {
        title: "Schedule rolling firmware maintenance",
        description:
          "Bake quarterly firmware windows into change calendars so gateways stay inside patch SLOs.",
        owner: "Infrastructure operations",
      },
      {
        title: "Document emergency takedown steps",
        description:
          "Record the exact commands and contacts needed to disable exposed services during an incident.",
        owner: "Incident response",
      },
    ],
    shortcuts: [
      {
        label: "RDP-only view",
        description: "Filter KEV for remote desktop exploits.",
        query: {
          domain: "Internet Edge",
          exploit: "Auth Bypass · Edge",
        },
      },
      {
        label: "SSH brute force",
        description: "Show SSH service CVEs to support hardening efforts.",
        query: {
          domain: "Internet Edge",
          vulnerability: "Authentication Bypass",
        },
      },
      {
        label: "Public PoCs",
        description: "Entries with readily available exploit tooling.",
        query: {
          domain: "Internet Edge",
          publicExploitOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "BlueKeep and friends",
        summary:
          "RDP vulnerabilities such as CVE-2019-0708 and its successors continue to drive worms and ransomware breakout.",
      },
      {
        title: "Cisco ASA / Firepower",
        summary:
          "Repeated Cisco ASA flaws demonstrate how remote services lead directly to credential theft and VPN hijacking.",
      },
    ],
    additionalInsights: [
      "Pair the rolling count with change calendars to prove the need for evergreen maintenance windows.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Network engineering", "Infrastructure operations"],
  },
  {
    slug: "web-injection-supply-chain",
    category: "theme",
    title: "Web Injection & Supply Chain",
    headline: "Web stack flaws cascade into downstream compromise",
    summary:
      "Expose why web application injection bugs should not be deprioritised just because they are \"only web\" issues.",
    hero: {
      kicker: "Focus page",
      description:
        "Use these insights when explaining to product owners how web exploitation translates to production outages, data loss, and supply-chain impact.",
    },
    filters: {
      domain: "Web Applications",
      vulnerability: "Remote Code Execution",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "totalMatches",
        label: "Attack surface overview",
        description: "Total KEV records attributed to web stacks within this slice of the catalog.",
      },
      {
        key: "publicExploitShare",
        label: "Known exploit availability",
        description: "Percentage of entries with public PoCs or Metasploit modules.",
      },
      {
        key: "pocWithin30DaysShare",
        label: "Exploit chain speed",
        description:
          "Share of CVEs where exploit material emerged within 30 days of disclosure, highlighting supply-chain risk.",
      },
      {
        key: "highSeverityShare",
        label: "High-severity concentration",
        description: "Portion of entries rated High or Critical by CVSS.",
      },
    ],
    narratives: [
      {
        title: "Supply-chain blast radius",
        body:
          "Many listings affect build servers, CI/CD orchestration, or third-party managed services. Use the incident summaries to illustrate cascading business impact.",
      },
    ],
    actions: [
      {
        title: "Apply WAF / API gateway mitigations",
        description:
          "Ship targeted rules that neutralise the exploit primitives described in each CVE while long-term patches roll out.",
        owner: "Application security",
      },
      {
        title: "Pin and verify dependencies",
        description:
          "Lock package versions, enable integrity checking, and add build-time verification for components referenced in these CVEs.",
        owner: "DevSecOps",
      },
      {
        title: "Update supply-chain documentation",
        description:
          "Record which third parties rely on the affected components so vendor management teams can confirm remediation timelines.",
        owner: "Vendor management",
      },
    ],
    shortcuts: [
      {
        label: "CMS exploits",
        description: "Highlight content management systems with active exploitation.",
        query: {
          domain: "Web Applications",
          search: "WordPress",
        },
      },
      {
        label: "Build server flaws",
        description: "Filter on CI/CD platforms and automation portals.",
        query: {
          domain: "Web Applications",
          search: "Jenkins",
        },
      },
      {
        label: "PoC required",
        description: "Constrain to entries with public PoC or Metasploit coverage.",
        query: {
          domain: "Web Applications",
          publicExploitOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "SolarWinds build compromise",
        summary:
          "Demonstrated how build pipeline intrusions propagate malicious updates downstream.",
      },
      {
        title: "Log4Shell fallout",
        summary:
          "CVE-2021-44228 showed how a single injection flaw across web stacks crippled operations worldwide.",
      },
    ],
    additionalInsights: [
      "Use the high-severity concentration metric to argue for mandatory change windows despite perceived \"low business impact\".",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Application security", "Vendor management"],
  },
  {
    slug: "email-collaboration-corridors",
    category: "theme",
    title: "Email & Collaboration Corridors",
    headline: "Collaboration stacks remain prime targets for initial access",
    summary:
      "Position mail and collaboration vulnerabilities as mission-critical risks by combining cadence metrics with actionable response ladders.",
    hero: {
      kicker: "Focus page",
      description:
        "SOC and IT responders can share this page with leadership to explain why collaboration suites demand the same urgency as edge devices.",
    },
    filters: {
      domain: "Mail Servers",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "rolling12MonthCount",
        label: "Rolling exploit cadence",
        description: "12-month trend for mail and collaboration KEV listings.",
      },
      {
        key: "internetExposedShare",
        label: "External exposure risk",
        description: "Percentage of entries involving internet-facing services.",
      },
      {
        key: "medianPatchWindowDays",
        label: "Patch adoption lag",
        description: "Median days between KEV listing and due date, highlighting change-control friction.",
      },
      {
        key: "dueDateCoverageShare",
        label: "Guidance availability",
        description: "Share of entries that include remediation scripts or hardening steps.",
      },
    ],
    narratives: [
      {
        title: "Incident readiness",
        body:
          "Use these numbers to justify readiness drills that combine IT, SOC, and communications teams when collaboration outages hit.",
      },
    ],
    actions: [
      {
        title: "Recommended response ladder",
        description:
          "Disable vulnerable endpoints, apply vendor patches, and run compromise assessments in a phased, rehearsed order.",
        owner: "Security operations",
      },
      {
        title: "Telemetry uplift",
        description:
          "Augment logging around Exchange, SharePoint, and collaboration APIs so defenders can detect abuse before full compromise.",
        owner: "Observability",
      },
      {
        title: "Stakeholder communication plan",
        description:
          "Keep customer success and communications partners looped in with templated updates for collaboration incidents.",
        owner: "Communications",
      },
    ],
    shortcuts: [
      {
        label: "Exchange vs others",
        description: "Compare Microsoft entries to other vendors.",
        query: {
          domain: "Mail Servers",
          search: "Microsoft",
        },
      },
      {
        label: "Public exploits",
        description: "Mail CVEs with public exploit tooling.",
        query: {
          domain: "Mail Servers",
          publicExploitOnly: true,
        },
      },
      {
        label: "Identity crossover",
        description: "Mail entries that also touch identity providers or collaboration APIs.",
        query: {
          domain: "Mail Servers",
          vulnerability: "Authentication Bypass",
        },
      },
    ],
    incidents: [
      {
        title: "ProxyNotShell",
        summary:
          "2022 Exchange flaws forced repeated emergency mitigations and highlighted the need for response ladders.",
      },
      {
        title: "Teams token theft",
        summary:
          "Abuse of collaboration tokens illustrated how attackers pivot from mail into chat ecosystems.",
      },
    ],
    additionalInsights: [
      "Pair cadence metrics with patch lag numbers when negotiating change freezes during peak business seasons.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Security operations", "Communications"],
  },
];
