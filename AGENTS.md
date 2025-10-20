# In the Wild

A lightweight dashboard and analytics tool for tracking actively exploited vulnerabilities across multiple feeds (CISA KEV, ENSISA and custom historical lists).

> Note: this repository contains code only. Do **not** start a dev server, run builds, or run tests — just write and review the code.


## Purpose

Provide companies and researchers with a compact, practical interface to view, filter, and analyze exploited-vulnerability feeds. The app highlights which vendors, products, and categories are most targeted in the wild and provides actionable, data-driven insights.

## Tech stack

| Layer     | Technology                                  |
|-----------|---------------------------------------------|
| Frontend  | Nuxt 4 + Nuxt UI v4 (see docs/nuxtui/)      |
| Styling   | TailwindCSS (via Nuxt UI)                   |
| Backend   | Supabase (Postgres + REST)                  |
| Data      | CISA KEV JSON/CSV, ENSISA, custom feeds     |
| Deployment| Static Nuxt site (with server routes)       |

See `NUXTUI.md` for Nuxt UI details.

## Core features

- **Import & update feeds** — fetch and store the latest CISA KEV, ENSISA, and custom lists.
- **Browse & filter** — search by CVE ID, vendor, product, category, vulnerability type, date added, or severity.
- **Statistics** — charts for top vendors, product categories, vulnerability families, and exploit frequency.
- **Trends** — visualize how exploited vulnerabilities evolve over time.
- **Export** — CSV download for filtered results.
- **Data provenance** — reference original feed entries and links to sources.


## Implementation

- Use Drizzle/Sqlite for storage.
- Normalize vendor/product names at import to improve grouping and statistics.
- Keep data schema minimal and audit-friendly (CVE, vendor, product, versions, feed source, date added, references, severity).
- Provide a server route to pull fresh feeds and an import job that upserts records.
- Do **not** include internal inventory integrations in the initial release — leave as an opt-in feature.


## Roadmap

- [] make all the badged from domain, exploit dynamics, vulnerbailtiy mix, date (just fitler for that year), cisa kev, , enisa , vendor, produ ct and so on clickable so it goes tothe catalog with that filter active, add to exisitng filters. have an otpion in the settings to have it clear the filtrers nad apply it a snew. but default to or .   
- [x] Add a dedicated poage for the vulns of the last two weeks. show as a list or cards in a grid 1 col or 2 cols. with a fancy card that has some detials about all the vulns.
- [ ] Add auth and persist my software to database per user
- [ ] Alerting (Slack / Email) when a new "in the wild" CVE matches saved filters.

# FIX 

it seems many metasploit modules are wrongly categorized as client side rce

Description	Date added	CVSS · EPSS	Domain · Exploit · Type	
Sangoma FreePBX Authentication Bypass Vulnerability

CISA KEV
ENISA
Metasploit modules
Server-side RCE · Non-memory
Sangoma FreePBX contains an authentication bypass vulnerability due to insufficiently sanitized user-supplied data allows unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution.

28.08.2025	
Critical 10.0
65.3%
Database & Storage
Non-Web Applications
Web Applications
Internet Edge
RCE · Server-side Non-memory
RCE · Client-side Non-memory
Remote Code Execution
Authentication Bypass
SQL Injection

Microsoft Windows External Control of File Name or Path Vulnerability

CISA KEV
ENISA
Metasploit modules
Microsoft Windows contains an external control of file name or path vulnerability that could allow an attacker to execute code from a remote WebDAV location specified by the WorkingDirectory attribute of Internet Shortcut files.

10.06.2025	
High 8.8
24.6%
Operating Systems
Non-Web Applications
Networking & VPN
RCE · Client-side Non-memory
Other
Remote Code Execution

Skyvern SSTI Remote Code Execution

Metasploit modules
This module exploits SSTI vulnerability in Skyvern<=0.1.84. The module requires API key to deliver requests and upload malicious workflow.

07.06.2025	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

Invision Community 5.0.6 customCss RCE

Metasploit modules
Invision Community up to and including version 5.0.6 contains a remote code execution vulnerability in the theme editor's customCss endpoint. By crafting a specially formatted `content` parameter with a `{expression="..."}` construct, arbitrary PHP can be evaluated. This module leverages that flaw to execute payloads or system commands as the webserver user.

16.05.2025	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

ConnectWise ScreenConnect Improper Authentication Vulnerability

CISA KEV
ENISA
Server-side RCE · Non-memory
ConnectWise ScreenConnect contains an improper authentication vulnerability. This vulnerability could allow a ViewState code injection attack, which could allow remote code execution if machine keys are compromised.

02.06.2025	
High 8.1
8.0%
Non-Web Applications
RCE · Client-side Non-memory
RCE · Server-side Non-memory
Remote Code Execution

Broadcom Brocade Fabric OS Code Injection Vulnerability

CISA KEV
ENISA
Broadcom Brocade Fabric OS contains a code injection vulnerability that allows a local user with administrative privileges to execute arbitrary code with full root privileges.

28.04.2025	
High 8.6
1.0%
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

ICTBroadcast Unauthenticated Remote Code Execution

Metasploit modules
This module exploits an unauthenticated remote code execution (RCE) vulnerability in ICTBroadcast. The vulnerability exists in the way session cookies are handled and processed, allowing an attacker to inject arbitrary system commands.

19.03.2025	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

FreeType Out-of-Bounds Write Vulnerability

CISA KEV
ENISA
FreeType contains an out-of-bounds write vulnerability when attempting to parse font subglyph structures related to TrueType GX and variable font files that may allow for arbitrary code execution.

06.05.2025	
High 8.1
67.1%
Non-Web Applications
RCE · Client-side Non-memory
Memory Corruption
Remote Code Execution

D-Tale RCE

Metasploit modules
This exploit effectively serves as a bypass for CVE-2024-3408. An attacker can override global state to enable custom filters, which then facilitates remote code execution. Specifically, this vulnerability leverages the ability to manipulate global application settings to activate the enable_custom_filters feature, typically restricted to trusted environments. Once enabled, the /test-filter endpoint of the Custom Filters functionality can be exploited to execute arbitrary system commands.

05.02.2025	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

D-Tale RCE

Metasploit modules
This exploit effectively serves as a bypass for CVE-2024-3408. An attacker can override global state to enable custom filters, which then facilitates remote code execution. Specifically, this vulnerability leverages the ability to manipulate global application settings to activate the enable_custom_filters feature, typically restricted to trusted environments. Once enabled, the /test-filter endpoint of the Custom Filters functionality can be exploited to execute arbitrary system commands.

05.02.2025	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

Unauthenticated RCE in NetAlertX

Metasploit modules
An attacker can update NetAlertX settings with no authentication, which results in RCE.

30.01.2025	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

7-Zip Mark of the Web Bypass Vulnerability

CISA KEV
ENISA
7-Zip contains a protection mechanism failure vulnerability that allows remote attackers to bypass the Mark-of-the-Web security feature to execute arbitrary code in the context of the current user.

06.02.2025	
High 7.0
30.9%
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS) unauthenticated Remote Code Execution

Metasploit modules
This exploit achieves unauthenticated remote code execution against BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS), with the privileges of the site user of the targeted BeyondTrust product site. This exploit targets PRA and RS versions 24.3.1 and below.

16.12.2024	
—
—
Operating Systems
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

Cleo Multiple Products Unauthenticated File Upload Vulnerability

CISA KEV
ENISA
Metasploit modules
Cleo Harmony, VLTrader, and LexiCom, which are managed file transfer products, contain an unrestricted file upload vulnerability that could allow an unauthenticated user to import and execute arbitrary bash or PowerShell commands on the host system by leveraging the default settings of the Autorun directory.

09.12.2024	
Critical 9.8
90.4%
Web Applications
Non-Web Applications
RCE · Client-side Non-memory
Command Injection
Remote Code Execution

Apple Multiple Products Code Execution Vulnerability

CISA KEV
ENISA
My software
Apple iOS, macOS, and other Apple products contain an unspecified vulnerability when processing maliciously crafted web content that may lead to arbitrary code execution.

21.11.2024	
High 8.8
0.7%
Operating Systems
Web Applications
Internet Edge
Browsers
Non-Web Applications
RCE · Client-side Non-memory
Remote Code Execution

Pyload RCE (CVE-2024-39205) with js2py sandbox escape (CVE-2024-28397)

Metasploit modules
CVE-2024-28397 is sandbox escape in js2py (<=0.74) which is a popular python package that can evaluate javascript code inside a python interpreter. The vulnerability allows for an attacker to obtain a reference to a python object in the js2py environment enabling them to escape the sandbox, bypass pyimport restrictions and execute arbitrary commands on the host. At the time of writing no patch has been released, version 0.74 is the latest version of js2py which was released Nov 6, 2022. CVE-2024-39205 is an remote code execution vulnerability in Pyload (<=0.5.0b3.dev85) which is an open-source download manager designed to automate file downloads from various online sources. Pyload is vulnerable because it exposes the vulnerable js2py functionality mentioned above on the /flash/addcrypted2 API endpoint. This endpoint was designed to only accept connections from localhost but by manipulating the HOST header we can bypass this restriction in order to access the API to achieve unauth RCE.

28.10.2024	
—
—
Operating Systems
