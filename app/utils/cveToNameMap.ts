// Map well-known, widely exploited CVEs to short canonical names.
// Keys are uppercase CVE identifiers.

export const cveToNameMap: Record<string, string> = {
  // 2003–2010 (worm era & SMB classics)
  'CVE-2003-0201': 'ECHOWRECKER', // Samba trans2open (Shadow Brokers leak)
  'CVE-2003-0694': 'EARLYSHOVEL', // Sendmail prescan DoS
  'CVE-2003-0818': 'kill-bill', // MS04-007 WebDAV buffer overflow
  'CVE-2004-1315': 'ESMARKCONANT', // phpBB highlight exploit
  'CVE-2005-2086': 'ESMARKCONANT', // phpBB highlight exploit
  'CVE-2008-4250': 'ECLIPSEDWING', // MS08-067 NetAPI
  'CVE-2009-2692': 'EXACTCHANGE', // Linux sock_sendpage privilege escalation
  'CVE-2009-3103': 'EDUCATEDSCHOLAR', // SMB2 negotiate/session handling
  'CVE-2010-2729': 'EMERALTHREAD', // Print Spooler privilege escalation

  // 2011–2014 (Heartbleed, Shellshock, Sandworm)
  'CVE-2011-3192': 'Apache Killer', // Apache httpd Range header DoS
  'CVE-2014-0160': 'Heartbleed', // OpenSSL heartbeat read
  'CVE-2014-3153': 'towelroot', // Android futex requeue privilege escalation
  'CVE-2014-3704': 'Drupageddon', // Drupal SQL injection
  'CVE-2014-4114': 'sandworm', // OLE Packager / PowerPoint
  'CVE-2014-6271': 'Shellshock', // Bash env vars (CGI)
  'CVE-2014-6278': 'Shellshock', // Bash function def variant
  'CVE-2014-6324': 'ESKIMOROLL', // Kerberos checksum

  // 2015–2016 (post-Heartbleed waves)
  'CVE-2015-0235': 'ghost', // glibc gethostbyname buffer overflow
  'CVE-2015-3864': 'stagefright', // Android media stack
  'CVE-2015-5119': '0DayFlush', // Hacking Team Adobe Flash 0-day
  'CVE-2016-3714': 'ImageTragick', // ImageMagick delegate abuse
  'CVE-2016-4557': 'double-fdput', // Linux BPF double free
  'CVE-2016-6366': 'EXTRABACON', // Cisco ASA SNMP RCE
  'CVE-2016-6415': 'BENIGNCERTAIN', // Cisco IKE information disclosure
  'CVE-2016-7976': 'ImageTragick', // ImageMagick uninitialized data

  // 2017 (Shadow Brokers fallout & Stack Clash)
  'CVE-2017-0143': 'DOUBLEPULSAR / EternalRomance/EternalSynergy / ETERNALBLUE', // MS17-010 family
  'CVE-2017-0144': 'ETERNALBLUE / DOUBLEPULSAR', // MS17-010 family
  'CVE-2017-0145': 'ETERNALBLUE / DOUBLEPULSAR', // MS17-010 family
  'CVE-2017-0146': 'EternalRomance/EternalSynergy / ETERNALBLUE / DOUBLEPULSAR', // MS17-010 family
  'CVE-2017-0147': 'EternalRomance/EternalSynergy / ETERNALBLUE / DOUBLEPULSAR', // MS17-010 family
  'CVE-2017-0148': 'ETERNALBLUE / DOUBLEPULSAR', // MS17-010 family
  'CVE-2017-5638': 'Struts2', // Apache Struts Jakarta (Equifax)
  'CVE-2017-7269': 'EXPLODINGCAN', // IIS WebDAV RCE
  'CVE-2017-8291': 'ghostbutt', // Ghostscript type confusion
  'CVE-2017-8461': 'ErraticGopher', // Windows RRAS RCE
  'CVE-2017-9798': 'Optionsbleed', // Apache httpd options leak
  'CVE-2017-1000364': 'Stack Clash', // Stack clash privilege escalation
  'CVE-2017-3622': 'EXTREMEPARR', // Solaris dtappgather privilege escalation
  'CVE-2017-3629': 'Stack Clash', // Stack clash variant
  'CVE-2017-3630': 'Stack Clash', // Stack clash variant
  'CVE-2017-3631': 'Stack Clash', // Stack clash variant

  // 2018
  'CVE-2018-1111': 'DynoRoot', // DHCP client command injection
  'CVE-2018-13379': 'FortiGate-SSL', // Fortinet FortiOS VPN creds

  // 2019
  'CVE-2019-0708': 'BlueKeep / Bluekeep', // RDP
  'CVE-2019-1458': 'WizardOpium', // Windows local privilege escalation
  'CVE-2019-19781': 'Shitrix', // Citrix ADC / NetScaler directory traversal
  'CVE-2019-5418': 'DoubleTap', // Rails file disclosure
  'CVE-2019-5420': 'doubletap', // Rails doubletap RCE chain

  // 2020 (supply-chain & infra)
  'CVE-2020-0796': 'SMBGhost', // SMBv3
  'CVE-2020-10148': 'SolarWinds', // SUNBURST supply-chain
  'CVE-2020-10914': 'This module', // Veeam One RCE
  'CVE-2020-10915': 'This module', // Veeam One RCE
  'CVE-2020-1350': 'SigRed', // Windows DNS server
  'CVE-2020-1472': 'Zerologon', // Netlogon elevation
  'CVE-2020-14882': 'WebLogic', // Oracle WebLogic RCE
  'CVE-2020-1938': 'Ghostcat', // Apache Tomcat AJP
  'CVE-2020-5902': 'F5BigIP', // F5 BIG-IP TMUI RCE
  'CVE-2020-6287': 'RECON', // SAP NetWeaver auth bypass

  // 2021 (Exchange, Log4j, PrintNightmare)
  'CVE-2021-1675': 'PrintNightmare', // Windows Print Spooler
  'CVE-2021-22015': 'vScalation', // vCenter privilege escalation
  'CVE-2021-26855': 'ProxyLogon', // Exchange Server SSRF
  'CVE-2021-27065': 'ProxyLogon', // Exchange Server file write
  'CVE-2021-31207': 'ProxyShell', // Exchange ProxyShell chain
  'CVE-2021-3156': 'Baron Samedit', // sudo heap overflow
  'CVE-2021-34473': 'ProxyShell', // Exchange ProxyShell chain
  'CVE-2021-34484': 'SuperProfile', // Windows User Profile Service
  'CVE-2021-34523': 'ProxyShell', // Exchange ProxyShell chain
  'CVE-2021-34527': 'PrintNightmare', // Windows Print Spooler
  'CVE-2021-36934': 'HiveNi', // SAM hive exposure
  'CVE-2021-38647': 'OMIGOD', // OMI unauth RCE
  'CVE-2021-38648': 'OMIGOD', // OMI privilege escalation
  'CVE-2021-40444': 'MSHTML', // MSHTML ActiveX / Office
  'CVE-2021-40539': 'ManageEngine', // Zoho ManageEngine ADSelfService+
  'CVE-2021-44228': 'Log4Shell', // Apache Log4j RCE
  'CVE-2021-45046': 'Log4Shell', // Log4j follow-up
  'CVE-2021-45105': 'Log4Shell', // Log4j follow-up

  // 2022
  'CVE-2022-0847': 'Dirty Pipe', // Linux kernel write-after-free
  'CVE-2022-1388': 'F5BigIP', // F5 BIG-IP TMUI (2022)
  'CVE-2022-21919': 'SuperProfile', // Windows User Profile Service
  'CVE-2022-21999': 'SpoolFool', // Windows Print Spooler
  'CVE-2022-22718': 'SpoolFool', // Windows Print Spooler
  'CVE-2022-22965': 'Spring4Shell', // Spring Framework
  'CVE-2022-26134': 'ConfluenceRCE', // Atlassian Confluence OGNL RCE
  'CVE-2022-26904': 'SuperProfile', // Windows User Profile Service
  'CVE-2022-26923': 'Certifried', // AD CS privilege escalation
  'CVE-2022-30190': 'Follina', // MSDT / Follina
  'CVE-2022-40684': 'FortiOS-AuthBypass', // Fortinet management auth bypass

  // 2023 (ransomware / high-impact web app)
  'CVE-2023-20198': 'CiscoIOS-XE', // Cisco IOS XE Web UI
  'CVE-2023-22515': 'Confluence-BrokenAuth', // Atlassian Confluence broken auth
  'CVE-2023-27350': 'PaperCut', // PaperCut MF/NG auth bypass
  'CVE-2023-27351': 'PaperCut', // PaperCut follow-up
  'CVE-2023-34362': 'MOVEit', // MOVEit SQLi exploited by CL0P (2023)
  'CVE-2023-3519': 'Citrix Bleed', // Citrix ADC (2023 families)
  'CVE-2023-38146': 'ThemeBleed', // Windows theme DLL hijack
  'CVE-2023-4966': 'Citrix Bleed', // Citrix ADC / NetScaler

  // 2024–2025 (high-signal additions)
  'CVE-2024-21626': 'Leaky Vessels', // runc container privilege escalation
  'CVE-2024-3400': 'PaloAlto-GlobalProtect', // Palo Alto PAN-OS GlobalProtect
  'CVE-2024-51978': 'Brother Default Admin Auth Bypass', // Brother device default admin bypass
}

export const normalizeCveKey = (raw: string): string => {
  // canonicalize common variants ("cve-2021-44228", "CVE202144228", "cve 2021 44228")
  const m = raw.toUpperCase().match(/CVE\D*?(\d{4})\D*?(\d{4,7})/)
  if (!m) return raw.toUpperCase()
  return `CVE-${m[1]}-${m[2]}`
}

export const lookupCveName = (rawCve: string): string | undefined => {
  const key = normalizeCveKey(rawCve)
  return cveToNameMap[key]
}
