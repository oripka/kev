// Map well-known, widely exploited CVEs to short canonical names.
// Keys are uppercase CVE identifiers.

export const cveToNameMap: Record<string, string> = {
  // historic / high-profile (still commonly referenced)
  'CVE-2014-0160': 'Heartbleed', // OpenSSL
  'CVE-2014-6271': 'Shellshock', // Bash env vars (CGI)

  // 2017
  'CVE-2017-0144': 'EternalBlue', // SMB / WannaCry
  'CVE-2017-0143': 'EternalRomance / EternalSynergy', // Type confusion between WriteAndX and Transaction requests
  'CVE-2017-0146': 'EternalChampion / EternalSynergy', // Race condition with Transaction requests
  'CVE-2017-0147': 'EternalRomance', // Reference used in EternalRomance exploit
  'CVE-2017-5638': 'Struts2', // Apache Struts Jakarta (Equifax)

  // 2018
  'CVE-2018-13379': 'FortiGate-SSL', // Fortinet FortiOS VPN creds

  // 2019
  'CVE-2019-0708': 'BlueKeep', // RDP
  'CVE-2019-19781': 'CitrixBleed', // Citrix ADC / NetScaler

  // 2020 (supply-chain & infra)
  'CVE-2020-10148': 'SolarWinds', // SUNBURST supply-chain
  'CVE-2020-0796': 'SMBGhost', // SMBv3
  'CVE-2020-1472': 'ZeroLogon', // Netlogon (Netlogon Elevation)
  'CVE-2020-1350': 'SigRed', // DNS (Windows DNS server)
  'CVE-2020-1938': 'Ghostcat', // Apache Tomcat AJP
  'CVE-2020-5902': 'F5BigIP', // F5 BIG-IP TMUI RCE
  'CVE-2020-14882': 'WebLogic', // Oracle WebLogic RCE

  // 2021 (Exchange, Log4j etc)
  'CVE-2021-26855': 'ProxyLogon', // Exchange Server (ProxyLogon)
  'CVE-2021-27065': 'ProxyLogon-FileWrite',
  'CVE-2021-31207': 'ProxyShell', // Exchange ProxyShell chain
  'CVE-2021-34473': 'ProxyShell',
  'CVE-2021-34523': 'ProxyShell',
  'CVE-2021-34527': 'PrintNightmare', // Windows Print Spooler
  'CVE-2021-40539': 'ManageEngine', // Zoho ManageEngine ADSelfService+
  'CVE-2021-44228': 'Log4Shell', // Apache Log4j RCE
  'CVE-2021-45046': 'Log4Shell', // Log4j follow-up
  'CVE-2021-45105': 'Log4Shell', // Log4j follow-up
  'CVE-2021-36934': 'HiveNightmare', // Windows (file ACL disclosure)
  'CVE-2021-40444': 'MSHTML', // MSHTML ActiveX / Office

  // 2022
  'CVE-2022-22965': 'Spring4Shell', // Spring Framework
  'CVE-2022-30190': 'Follina', // MSDT / Follina
  'CVE-2022-1388': 'F5BigIP', // F5 BIG-IP TMUI (2022)
  'CVE-2022-26134': 'ConfluenceRCE', // Atlassian Confluence OGNL RCE
  'CVE-2022-40684': 'FortiOS-AuthBypass', // Fortinet management auth bypass

  // 2023 (ransomware / high-impact web app)
  'CVE-2023-34362': 'MOVEit', // MOVEit SQLi exploited by CL0P (2023)
  'CVE-2023-27350': 'PaperCut', // PaperCut MF/NG (2023)
  'CVE-2023-27351': 'PaperCut', // PaperCut follow-up
  'CVE-2023-3519': 'CitrixBleed', // Citrix ADC (2023 families)
  'CVE-2023-4966': 'CitrixBleed', // Citrix ADC (2023 families)
  'CVE-2023-20198': 'CiscoIOS-XE', // Cisco IOS XE Web UI
  'CVE-2023-22515': 'Confluence-BrokenAuth', // Atlassian Confluence Broken Access Control

  // 2024–2025 (notable/early 2025 additions - include high-confidence items only)
  // (If you want the latest KEV additions programmatically, pull CISA KEV JSON.)
  'CVE-2024-3400': 'PaloAlto-GlobalProtect', // Palo Alto PAN-OS GlobalProtect
  // examples left blank for you to extend as you ingest KEV updates
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
