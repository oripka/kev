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
  icon?: string;
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
    icon: "i-lucide-globe-lock",
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
    icon: "i-lucide-router",
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
    icon: "i-lucide-mail-warning",
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
    icon: "i-lucide-cpu",
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
    slug: "web-server-hardening",
    category: "critical",
    title: "Web Server Entry Points",
    headline: "Keep front-of-house servers hardened to stop hands-on-keyboard breaches",
    summary:
      "Recurring Apache, Nginx, and IIS flaws show how quickly exposed web infrastructure converts into ransomware footholds.",
    icon: "i-lucide-server-cog",
    hero: {
      kicker: "Critical focus",
      description:
        "Platform, infrastructure, and incident teams can point to these metrics when requesting maintenance windows for reverse proxies and load balancers.",
    },
    filters: {
      domain: "Web Servers",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "fiveYearMatchCount",
        label: "Five-year exploit count",
        description:
          "Total KEV entries tied to web server software across the five-year window.",
      },
      {
        key: "publicExploitShare",
        label: "Commodity exploit share",
        description:
          "Percentage of listings with public PoCs or Metasploit modules, signalling rapid weaponisation.",
      },
      {
        key: "medianExploitWindowDays",
        label: "Median time to weaponisation",
        description:
          "Median number of days between disclosure and KEV listing for web server CVEs.",
      },
      {
        key: "dueDateCoverageShare",
        label: "Remediation guidance coverage",
        description:
          "Portion of entries where vendors supplied mitigation or patch guidance defenders can execute.",
      },
    ],
    narratives: [
      {
        title: "Incident driver",
        body:
          "Compromised web servers routinely hand over credentials and VPN sessions. Use this focus page to demonstrate why reverse proxies and app servers demand the same rigor as VPN gateways.",
      },
      {
        title: "Change control friction",
        body:
          "Present the exploit cadence to change advisory boards so they reserve recurring downtime for front-end infrastructure.",
      },
    ],
    actions: [
      {
        title: "Baseline patch windows",
        description:
          "Schedule standing maintenance windows for web servers and reverse proxies, even during peak seasons.",
        owner: "Platform engineering",
      },
      {
        title: "Tighten surface telemetry",
        description:
          "Ensure request logging, WAF telemetry, and canary endpoints exist for the products highlighted in the list.",
        owner: "Security operations",
      },
      {
        title: "Codify emergency rollback",
        description:
          "Document and rehearse the exact steps to fail traffic over or disable a vulnerable tier when KEV adds a new entry.",
        owner: "Infrastructure operations",
      },
    ],
    shortcuts: [
      {
        label: "Reverse proxy RCEs",
        description: "Highlight Apache HTTP Server, Nginx, and F5 BIG-IP issues.",
        query: {
          domain: "Web Servers",
          search: "Apache",
        },
      },
      {
        label: "Windows IIS stack",
        description: "Focus on Microsoft IIS and Exchange web services exposure.",
        query: {
          domain: "Web Servers",
          search: "IIS",
        },
      },
      {
        label: "PoC available",
        description: "Restrict to web server CVEs with public exploit tooling.",
        query: {
          domain: "Web Servers",
          publicExploitOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "ProxyShell & ProxyLogon",
        summary:
          "Sequential Exchange web tier flaws underpinned multiple ransomware campaigns and credential theft operations.",
      },
      {
        title: "Apache Struts CVE-2017-5638",
        summary:
          "The breach that compromised Equifax remains a touchstone example of why web servers require urgent patching.",
      },
    ],
    highlightNotes: [
      "Web servers remain one of the fastest paths from external exposure to internal credential theft.",
      "Commodity exploit support means attackers can reuse payloads faster than operations teams can request downtime.",
    ],
    keySignalNotes: [
      "Track the median time to weaponisation to defend patch window requests with data.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Platform engineering", "Infrastructure operations"],
  },
  {
    slug: "browser-attack-surface",
    category: "critical",
    title: "Browser Exploit Frontlines",
    headline: "Modern browsers are a primary zero-day delivery channel",
    summary:
      "Chromium, WebKit, and Gecko vulnerabilities continue to deliver implants via drive-by downloads and social engineering.",
    icon: "i-lucide-globe-2",
    hero: {
      kicker: "Critical focus",
      description:
        "Endpoint engineering and threat hunters can use this page to justify aggressive auto-update cadence and isolation investments.",
    },
    filters: {
      domain: "Browsers",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "rolling12MonthCount",
        label: "12-month exploit cadence",
        description:
          "Rolling total of KEV browser listings captured over the past year.",
      },
      {
        key: "pocWithin30DaysShare",
        label: "0-day conversion rate",
        description:
          "Share of listings where exploit material surfaced within 30 days of disclosure.",
      },
      {
        key: "publicExploitShare",
        label: "Exploit kit presence",
        description:
          "Percentage of entries with public PoCs or integration into exploit frameworks.",
      },
      {
        key: "medianPatchWindowDays",
        label: "Patch adoption window",
        description:
          "Median time between KEV listing and vendor due dates, indicating how fast desktops must update.",
      },
    ],
    narratives: [
      {
        title: "Targeting executives and developers",
        body:
          "Drive-by campaigns routinely aim at people with elevated access, making browser hygiene a board-level concern.",
      },
      {
        title: "Autoupdate coverage gaps",
        body:
          "Use the cadence numbers to prove why disabling or delaying browser auto-updates leaves enterprises exposed.",
      },
    ],
    actions: [
      {
        title: "Enforce rapid auto-update",
        description:
          "Audit fleet coverage for Chrome, Edge, Firefox, and Safari to ensure updates land within hours not weeks.",
        owner: "Endpoint engineering",
      },
      {
        title: "Expand browser isolation",
        description:
          "Deploy isolation or remote browsing for high-risk personas when KEV adds a new browser zero-day.",
        owner: "Security architecture",
      },
      {
        title: "Hunt for exploit leftovers",
        description:
          "Instrument telemetry to detect crash loops, sandbox escapes, and suspicious renderer processes post-patch.",
        owner: "Threat detection",
      },
    ],
    shortcuts: [
      {
        label: "Chromium family",
        description: "Entries affecting Chrome, Edge, and other Chromium derivatives.",
        query: {
          domain: "Browsers",
          search: "Chrome",
        },
      },
      {
        label: "Safari & WebKit",
        description: "Highlight Apple-centric browser vulnerabilities.",
        query: {
          domain: "Browsers",
          search: "Safari",
        },
      },
      {
        label: "Exploit kit ready",
        description: "Browser CVEs with public exploit material or Metasploit modules.",
        query: {
          domain: "Browsers",
          publicExploitOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "Chrome zero-day clusters",
        summary:
          "Repeated Chrome in-the-wild zero-days during 2023–2024 showed how quickly exploit brokers weaponise renderer bugs.",
      },
      {
        title: "WebKit spyware deployment",
        summary:
          "Mobile spyware crews leveraged WebKit flaws to deliver implants through a single malicious link.",
      },
    ],
    highlightNotes: [
      "Browser zero-days are increasingly brokered and reused across multiple threat groups.",
      "Fast autoupdate is the most reliable mitigation when KEV lists a new browser CVE.",
    ],
    keySignalNotes: [
      "Monitor the 0-day conversion rate to assess whether defensive isolation is keeping pace with attacker agility.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["Endpoint engineering", "Security architecture"],
  },
  {
    slug: "client-application-exposure",
    category: "critical",
    title: "Client Application Footholds",
    headline: "Remote support and business apps create quiet persistence spots",
    summary:
      "Non-web client software such as remote access, backup, and IT tooling continues to deliver initial access for ransomware crews.",
    icon: "i-lucide-laptop-2",
    hero: {
      kicker: "Critical focus",
      description:
        "Desktop engineering and IT operations can point to these insights when tightening application allowlists and vendor patch obligations.",
    },
    filters: {
      domain: "Non-Web Applications",
      sources: defaultSources,
    },
    metrics: [
      {
        key: "fiveYearMatchCount",
        label: "Five-year exposure count",
        description:
          "Total KEV entries attributed to client-side business software across five years.",
      },
      {
        key: "highSeverityShare",
        label: "High/critical severity share",
        description:
          "Portion of listings rated High or Critical by CVSS, indicating immediate risk.",
      },
      {
        key: "pocWithin30DaysShare",
        label: "Exploit availability speed",
        description:
          "Share of entries where public PoCs emerged within 30 days, highlighting weaponisation speed.",
      },
      {
        key: "ransomwareShare",
        label: "Ransomware linkage",
        description:
          "Percentage of entries explicitly tied to ransomware operations in KEV commentary.",
      },
    ],
    narratives: [
      {
        title: "Remote management blind spots",
        body:
          "Tools installed by help desks or MSPs often escape standard hardening. Bring this data to procurement and onboarding reviews.",
      },
      {
        title: "Vendor accountability",
        body:
          "Use the ransomware linkage metric to insist partners keep remote support agents patched or segmented.",
      },
    ],
    actions: [
      {
        title: "Harden remote access tools",
        description:
          "Require MFA, restrict network reach, and enforce rapid patching for highlighted remote management software.",
        owner: "IT operations",
      },
      {
        title: "Expand application allowlisting",
        description:
          "Limit where remote support and backup agents can run, disabling unused modules by default.",
        owner: "Endpoint engineering",
      },
      {
        title: "Practice compromise drills",
        description:
          "Rehearse incident response scenarios where adversaries abuse remote support agents to deploy ransomware.",
        owner: "Incident response",
      },
    ],
    shortcuts: [
      {
        label: "Remote support tooling",
        description: "Entries covering ScreenConnect, TeamViewer, and similar agents.",
        query: {
          domain: "Non-Web Applications",
          search: "ConnectWise",
        },
      },
      {
        label: "File transfer clients",
        description: "Focus on backup and file transfer software leveraged in intrusions.",
        query: {
          domain: "Non-Web Applications",
          search: "GoAnywhere",
        },
      },
      {
        label: "Known ransomware",
        description: "Client software CVEs linked to ransomware activity.",
        query: {
          domain: "Non-Web Applications",
          ransomwareOnly: true,
        },
      },
    ],
    incidents: [
      {
        title: "ScreenConnect exploitation",
        summary:
          "The 2024 ScreenConnect vulnerability led to widespread ransomware deployment via remote support agents.",
      },
      {
        title: "GoAnywhere MFT abuse",
        summary:
          "Managed file transfer clients were a common launchpad for extortion crews, underscoring vendor hardening gaps.",
      },
    ],
    highlightNotes: [
      "Client tools installed for convenience often become unmonitored persistence mechanisms.",
      "Ransomware groups rapidly incorporate remote support CVEs into playbooks once public PoCs appear.",
    ],
    keySignalNotes: [
      "Watch the ransomware-linked share to prioritise which agents should be removed or segmented first.",
    ],
    timelinePeriod: "monthly",
    recommendedOwners: ["IT operations", "Endpoint engineering"],
  },
];
