import type {
  KevDomainCategory,
  KevEntry,
  KevExploitLayer,
  KevVulnerabilityCategory
} from '~/types'

export type KevBaseEntry = Omit<
  KevEntry,
  'domainCategories' | 'exploitLayers' | 'vulnerabilityCategories'
>

const domainRules: Array<{
  category: KevDomainCategory
  patterns: RegExp[]
}> = [
  {
    category: 'Mail Servers',
    patterns: [/(exchange|outlook|postfix|qmail|sendmail|smtp|mailman|zimbra|lotus)/i]
  },
  {
    category: 'Security Appliances',
    patterns: [/(fortinet|palo alto|checkpoint|sonicwall|watchguard|firepower|intrusion prevention|ips|ids|securepoint)/i]
  },
  {
    category: 'Networking & VPN',
    patterns: [/(router|switch|vpn|network|gateway|sd-wan|wireless|wifi|firewall|load balancer|edge|proxy)/i]
  },
  {
    category: 'Browsers',
    patterns: [
      /(browser|chrome|firefox|edge|safari|webkit|chromium|brave|opera|internet explorer|msie|trident)/i
    ]
  },
  {
    category: 'Web Applications',
    patterns: [
      /(wordpress|drupal|joomla|magento|confluence|jira|sharepoint|portal|cms|web application|owa|webmail|jenkins|phpmailer|whatsup gold|commvault|command center|manageengine|grafana|kibana|splunk|tableau|apache (?:struts|ofbiz)|weblogic|wildfly|liferay|alfresco|sap (?:netweaver|portal)|cacti|zabbix|nagios)/i
    ]
  },
  {
    category: 'Web Servers',
    patterns: [
      /(apache (?:http server|httpd))/i,
      /(nginx)/i,
      /(internet information services|microsoft iis|iis)/i,
      /(apache tomcat|tomcat|catalina)/i,
      /(jetty)/i,
      /(lighttpd)/i,
      /(caddy|openresty)/i
    ]
  },
  {
    category: 'Operating Systems',
    patterns: [/(windows|linux|macos|ios|ipad|android|unix|solaris|aix|hp-ux|red hat|ubuntu)/i]
  },
  {
    category: 'Industrial Control Systems',
    patterns: [/(ics|scada|plc|siemens|rockwell|schneider electric|abb|industrial)/i]
  },
  {
    category: 'Virtualization & Containers',
    patterns: [/(vmware|esxi|vsphere|vcenter|hyper-v|virtualization|xen|kubernetes|docker|container)/i]
  },
  {
    category: 'Cloud & SaaS',
    patterns: [/(cloud|azure|aws|salesforce|service-now|servicenow|google workspace|office 365|okta|auth0)/i]
  },
  {
    category: 'Database & Storage',
    patterns: [/(database|sql server|mysql|postgres|oracle|mongodb|db2|couchbase|sap hana|storage|nas|netapp|iscsi)/i]
  }
]

const internetEdgeDomainHints: KevDomainCategory[] = [
  'Networking & VPN',
  'Web Applications',
  'Web Servers',
  'Mail Servers',
  'Cloud & SaaS',
  'Security Appliances'
]

const matchesAny = (value: string, patterns: RegExp[]) =>
  patterns.some(pattern => pattern.test(value))

type CvssVectorTraits = {
  attackVector?: 'P' | 'L' | 'A' | 'N'
  privilegesRequired?: 'N' | 'L' | 'H'
  userInteraction?: 'N' | 'R'
}

const parseCvssVector = (vector?: string | null): CvssVectorTraits | null => {
  if (!vector) {
    return null
  }

  const metrics: Record<string, string> = {}
  const tokens = vector.trim().split('/')

  for (const token of tokens) {
    const [metric, value] = token.split(':')
    if (!value) {
      continue
    }

    const upperMetric = metric.toUpperCase()
    if (upperMetric === 'AV' || upperMetric === 'PR' || upperMetric === 'UI') {
      metrics[upperMetric] = value.toUpperCase()
    }
  }

  if (!metrics.AV && !metrics.PR && !metrics.UI) {
    return null
  }

  return {
    attackVector: metrics.AV as CvssVectorTraits['attackVector'] | undefined,
    privilegesRequired: metrics.PR as CvssVectorTraits['privilegesRequired'] | undefined,
    userInteraction: metrics.UI as CvssVectorTraits['userInteraction'] | undefined
  }
}
const edgeStrongProductPatterns: RegExp[] = [
  /(citrix (?:adc|netscaler|gateway|workspace))/i,
  /(netscaler)/i,
  /(pulse (?:secure|connect secure))/i,
  /(ivanti (?:connect secure|policy secure|secure access))/i,
  /(globalprotect)/i,
  /(pan-?os)/i,
  /(forti(?:gate|os|web|proxy|wan))/i,
  /(big[- ]?ip|f5\s*(?:big[- ]?ip|traffic manager))/i,
  /(zscaler)/i,
  /(barracuda (?:cloudgen|ssl vpn|remote access))/i,
  /(sonicwall)/i,
  /(check point)/i,
  /(cisco (?:asa|anyconnect|secure (?:desktop|firewall)|vpn))/i,
  /(secure mobile access)/i,
  /(remote desktop (?:gateway|web access)|rd\s?(?:gateway|web))/i,
  /(microsoft exchange|exchange server|exchange online)/i,
  /(outlook web access|owa)/i
]

const edgeSupportingProductPatterns: RegExp[] = [
  /(sharepoint)/i,
  /(jira)/i,
  /(confluence)/i,
  /(bitbucket)/i,
  /(gitlab)/i,
  /(workspace one)/i,
  /(vpn (?:portal|gateway))/i
]

const edgeContextPatterns: RegExp[] = [
  /(ssl[- ]?vpn)/i,
  /(clientless vpn)/i,
  /(vpn (?:portal|gateway|service|interface|server))/i,
  /(remote (?:access|portal|service|authentication|desktop))/i,
  /(internet[- ]?facing|public[- ]?facing|externally accessible|exposed to the internet)/i,
  /(edge (?:device|gateway|service))/i,
  /(webvpn)/i,
  /(citrix (?:gateway|netscaler|adc))/i,
  /(rd\s?web|rdweb|remote desktop (?:web|gateway))/i,
  /(outlook web access|owa)/i,
  /(exchange web services|ews)/i
]

const edgePortalPatterns: RegExp[] = [
  /(web (?:portal|login|interface|console|client))/i,
  /(portal (?:access|login|interface))/i,
  /(remote portal)/i,
  /(vpn web (?:portal|interface))/i
]

const edgeMailPatterns: RegExp[] = [
  /(microsoft exchange|exchange server|exchange online)/i,
  /(outlook web access|owa)/i,
  /(exchange web services|ews)/i
]

const webProductPatterns: RegExp[] = [
  /(jenkins)/i,
  /(phpmailer)/i,
  /(apache (?:struts|ofbiz|roller|felix))/i,
  /(weblogic|websphere|glassfish|wildfly|jboss)/i,
  /(wordpress|drupal|joomla|magento|opencart|prestashop|woocommerce)/i,
  /(confluence|jira|bitbucket|crowd|bamboo)/i,
  /(sharepoint|liferay|alfresco|sitecore|strapi)/i,
  /(coldfusion)/i,
  /(e-?business suite|ebs)/i,
  /(bi publisher)/i,
  /(netweaver)/i,
  /(manageengine|servicedesk|adselfservice|opmanager|desktop central)/i,
  /(endpoint manager)/i,
  /(grafana|kibana|splunk|tableau|superset)/i,
  /(sap (?:portal|netweaver|commerce|hybris))/i,
  /(progress.*whatsup gold|whatsup gold)/i,
  /(commvault.*command center|command center)/i,
  /(zimbra|roundcube|webmail|owa|outlook web)/i,
  /(phpmyadmin|cacti|zabbix|nagios|pfsense)/i,
  /(gitlab|gitbucket|gitea|bitbucket)/i,
  /(ip camera|nvr|dvr|webcam)/i,
  /(qlik\s*sense)/i,
  /(goanywhere)/i,
  /(crushftp)/i,
  /(pulse connect secure)/i,
  /(cityworks)/i,
  /(jasperreports)/i,
  /(langflow)/i,
  /(simplehelp)/i,
  /(projectsend)/i,
  /(veracore)/i,
  /(adminer)/i,
  /(identity services engine|cisco ise)/i,
  /(apex one)/i,
  /(sysaid)/i,
  /(fortiweb)/i,
  /(telemessages?)/i,
  /(sonicwall)/i,
  /(md[a]?emon)/i,
  /(geovision)/i,
  /(rails)/i,
  /(jquery)/i,
  /(cobalt strike)/i,
  /(flash player)/i,
  /(vcenter)/i,
  /(imagemagick)/i,
  /(connect secure|policy secure|neurons)/i,
  /(n[- ]?central)/i,
  /(aviatrix)/i,
  /(beyondtrust)/i,
  /(privileged remote access|remote support)/i,
  /(cloud services appliance|csa)/i,
  /(velo?cloud)/i,
  /(sd[- ]?wan (?:edge|orchestrator|controller))/i,
  /(spring (?:boot|framework|cloud|data|security|mvc|core|commons))/i,
  /(adobe experience manager|aem forms|aem)/i,
  /(draytek|vigor[0-9]+)/i,
  /(sonicos)/i,
  /(fortios)/i,
  /(exchange (?:server)?)/i,
  /(proxylogon)/i,
  /(sophos)/i,
  /(tp-?link|tplink)/i,
  /(archer)/i,
  /(d-?link)/i,
  /(cisco (?:asa|adaptive security appliance))/i,
  /\badaptive security appliance\b/i,
  /\bwebvpn\b/i
]

const webServerPatterns: RegExp[] = [
  /(apache (?:http server|httpd))/i,
  /(nginx)/i,
  /(internet information services|microsoft iis|iis)/i,
  /(apache tomcat|tomcat|catalina)/i,
  /(jetty)/i,
  /(lighttpd)/i,
  /(caddy|openresty)/i
]

const webDevicePatterns: RegExp[] = [
  /(ip camera|nvr|dvr|webcam|nas)/i,
  /(router|gateway|access point|wireless controller|firewall|ap)/i,
  /(security appliance|vpn appliance)/i
]

const webNegativePatterns: RegExp[] = [
  /(internet explorer)/i,
  /(google chrome)/i,
  /(mozilla firefox)/i,
  /(microsoft edge)/i,
  /(safari)/i,
  /(brave)/i,
  /(opera)/i,
  /(vivaldi)/i,
  /\bbrowser\b/i
]

const webIndicatorPatterns: RegExp[] = [
  /(cross[- ]?site scripting|xss)/i,
  /(xml external entity|xxe)/i,
  /(server[- ]?side request forgery|ssrf)/i,
  /(sql injection|sqli)/i,
  /(directory traversal|path traversal)/i,
  /(?:\.\.\/){1,}/i,
  /(remote file inclusion|rfi)/i,
  /(open redirect|url redirect)/i,
  /(arbitrary (?:file|code) upload|file upload|file download)/i,
  /(command injection|os command)/i,
  /(template injection|twig|freemarker)/i,
  /(cross[- ]?site request forgery|csrf)/i,
  /\.(?:php|jsp|asp|aspx|cgi|pl|js)\b/i,
  /(\/[a-z0-9._-]+){1,}\/[a-z0-9._-]+\.(?:php|jsp|asp|aspx|cgi|pl|js)/i,
  /\bwebvpn\b/i
]

const webStrongContextPatterns: RegExp[] = [
  /(web (?:interface|console|ui|portal|application|service|dashboard|admin|client))/i,
  /(management (?:interface|portal|console|ui|plane|dashboard|panel))/i,
  /(admin(?:istrator)? (?:interface|portal|console|ui|dashboard|panel))/i,
  /(administrative (?:interface|portal|console|ui|dashboard|panel))/i,
  /(super-?admin)/i,
  /(control panel|control plane|control center)/i,
  /(login (?:portal|page|interface|screen|panel))/i,
  /(server url)/i,
  /(parental control page)/i,
  /(browser[- ]?based|web[- ]?based)/i,
  /(web content)/i,
  /(?:via|over)\s+https?/i,
  /https?:\/\//i,
  /\bhttp\b[^.]*\b(request|response|endpoint|header|parameter|query)\b/i,
  /https?\s*(?:request|requests|response|responses)/i,
  /(crafted[^.]{0,40}https?)/i,
  /(cgi[-/]bin)/i,
  /(\/userRpm\/)/i,
  /(http post (?:request|handler))/i,
  /\bwebvpn\b/i,
  /(vpn (?:web )?portal)/i,
  /(\/[a-z0-9_-]*api\b)/i,
  /(rest api|graphql|soap api|json-rpc)/i,
  /(csrf|cross[- ]?site request forgery)/i,
  /(deserialization|serialized object)/i,
  /(crafted (?:http )?requests?)/i,
  /(cgi|servlet)/i,
  /(httpd)/i,
  /(web server)/i,
  /(vpn web server)/i,
  /(api (?:request|response|endpoint|call))/i,
  /(?:rest|graphql|soap|json)\s+api/i,
  /\b(?:get|post|put|delete|patch)\s+requests?\b/i
]

const webDeviceContextPatterns: RegExp[] = [
  /(web interface|web management|web console|browser)/i,
  /https?:\/\//i,
  /(crafted requests?)/i,
  /\bhttp\b/i,
  /(cgi)/i
]

const webManagementPatterns: RegExp[] = [
  /(management (?:interface|portal|console|ui|plane|dashboard|panel))/i,
  /(admin(?:istrator)? (?:interface|portal|console|ui|dashboard|panel))/i,
  /(administrative (?:interface|portal|console|ui|dashboard|panel))/i,
  /(admin(?:istrator)? account)/i,
  /(super-?admin)/i,
  /(control panel|control plane|control center)/i,
  /(login (?:portal|page|interface|screen|panel))/i,
  /(server url)/i,
  /\bwebvpn\b/i
]

const webApiPatterns: RegExp[] = [
  /(rest(?:ful)? api)/i,
  /(graphql api)/i,
  /(soap api)/i,
  /(json api)/i,
  /(web api)/i,
  /(api endpoint)/i,
  /(api interface)/i,
  /(api (?:request|response|call|gateway|server))/i,
  /\/api\b/i
]

const nonWebProductPatterns: RegExp[] = [
  /(kernel|driver|firmware|microcode|bootloader|hypervisor)/i,
  /(common log file system|clfs)/i,
  /(sandbox escape)/i,
  /(microsoft management console|\bmmc\b)/i
]

const nonWebContextPatterns: RegExp[] = [
  /(physical access)/i,
  /(local privilege escalation|locally)/i,
  /(stack[- ]?based buffer overflow|heap[- ]?based buffer overflow|buffer overflow|out[- ]?of[- ]?bounds|use[- ]?after[- ]?free|memory corruption)/i,
  /(command line interface|\bcli\b)/i
]

const privilegePatterns: RegExp[] = [
  /(privilege escalation|elevation of privilege|gain[s]? (?:administrative|root|privileges?)|eop)/i
]

const remoteExecutionPatterns: RegExp[] = [
  /(remote code execution)/i,
  /(execute code remotely)/i,
  /(remote execution)/i,
  /\bRCE\b/i
]

const codeExecutionPatterns: RegExp[] = [
  /(execute arbitrary code)/i,
  /(arbitrary code execution)/i,
  /(run arbitrary code)/i,
  /(code[- ]?execution)/i
]

const remoteContextPatterns: RegExp[] = [
  /(remote (?:attacker|user|actor|threat))/i,
  /(remote,? (?:unauthenticated|authenticated) attacker)/i,
  /\bremotely\b/i,
  /(over the network|across the network|network[- ]based attacker|network access)/i,
  /(via (?:the )?network)/i,
  /(via (?:http|https|smb|rpc|rdp|ftp|smtp|imap|pop3|dns|tcp|udp|ldap|snmp|modbus|dce\/?rpc))/i,
  /(through (?:http|https|smb|rpc|rdp|ftp|smtp|imap|pop3|dns|tcp|udp|ldap|snmp|modbus|dce\/?rpc))/i,
  /(crafted (?:request|packet|payload|network request|network traffic|network message))/i
]


// Enhanced and safer regexes to detect memory corruption vulnerabilities
const memoryCorruptionPatterns: RegExp[] = [
  // General memory corruption
  /\bmemory (?:corruption|corrupt(?:ed)?)\b/i,

  // Buffer overflows and similar
  /\b(?:buffer(?:[-\s]?(?:overflow|overrun|underflow|underrun))|stack(?:[-\s]?(?:overflow|overrun))|heap(?:[-\s]?(?:overflow|corruption)))\b/i,

  // Out-of-bounds — ensure bounded by non-word chars to avoid OOB inside words
  /(?:^|[^a-z0-9])(out[-\s]?of[-\s]?bounds|oob)(?: (?:read|write|access|r\/w|w\/r))?(?=[^a-z0-9]|$)/i,

  // Off-by-one
  /\boff[-\s]?by[-\s]?one(?: (?:overflow|read|write|error))?\b/i,

  // Use-after-free & pointer issues
  /\b(use[-\s]?after[-\s]?free|use[-\s]?after[-\s]?scope|double[-\s]?free|dangling (?:pointer|reference)|invalid pointer)\b/i,

  // Heap/stack corruption
  /\b(?:heap corruption|stack corruption|heap[-\s]?overflow|stack[-\s]?overflow)\b/i,

  // Write primitives and overwrite issues
  /\b(?:write[-\s]?(?:what[-\s]?where)|arbitrary write|controlled write|partial overwrite|wild write)\b/i,

  // Integer overflow / underflow
  /\b(?:integer (?:overflow|underflow)|signedness (?:error|issue))\b/i,

  // Format string vulns that cause memory corruption
  /\bformat[-\s]?string(?: vulnerability| bug)?\b/i
];


const denialOfServicePatterns: RegExp[] = [
  // explicit denial-of-service phrases (keeps "dos" only when part of "dos attack" or as DDoS/DoS forms)
  /\b(?:denial[-\s]?of[-\s]?service|denial[-\s]?of[-\s]?service attack|dos attack)\b/i,
  /\b(?:ddo?s(?:[-\s]?attack)?|d\.?d\.?o\.?s)\b/i, // matches DDoS / DoS / D.D.O.S forms (but not generic 'dos' words when used in context)

  // resource exhaustion / leaks / allocation storms
  /\b(?:resource(?:[-\s]?exhaustion| exhaustion)|memory(?:[-\s]?exhaustion| exhaustion| leak| pressure)|out[-\s]?of[-\s]?memory|oom(?: killer)?\b)/i,
  /\b(?:cpu(?:[-\s]?exhaustion| exhaustion| spike| high(?:[-\s]?cpu| load)?)|high(?:[-\s]?cpu|[-\s]?load|[-\s]?utilization))\b/i,

  // crashes, panics, segfaults — kept as whole words to avoid noise
  /\b(?:crash(?:es|ed)?|panic(?:s)?|segmentation fault|segfault|kernel panic)\b/i,

  // hangs / unresponsive / infinite loops / busy/spin loops
  /\b(?:hang(?:s|ing)?|unresponsive|freeze|stuck|infinite(?:[-\s]?loop)?|busy(?:[-\s]?loop|loop)|spin(?:[-\s]?lock)?)\b/i,

  // flooding / request abuse / connection exhaustion / socket exhaustion / rate-limit bypass
  /\b(?:flood(?:ing|ed)?|request(?:[-\s]?flood|[-\s]?storm)?|connection(?:[-\s]?flood|[-\s]?exhaustion|[-\s]?storm)|socket(?:[-\s]?exhaustion)?)\b/i,
  /\b(?:rate[-\s]?limit(?:ing)? bypass|rate[-\s]?limit(?:ing)?|throttl(?:e|ing) bypass|throttle(?:ing)?)\b/i,

  // fork bombs, descriptor exhaustion, handle exhaustion
  /\b(?:fork[-\s]?bomb|file[-\s]?descriptor(?:[-\s]?exhaustion)?|fd(?:[-\s]?exhaustion)?|handle(?:[-\s]?exhaustion)?)\b/i,

  // patterns describing DoS cause (infinite accept loop, busy polling, allocate loop, thread leak)
  /\b(?:thread(?:[-\s]?leak)|handle(?:[-\s]?leak)|descriptor(?:[-\s]?leak)|socket(?:[-\s]?leak)|allocation(?:[-\s]?storm)|memory(?:[-\s]?blast|[-\s]?storm))\b/i,

  // other DoS-related primitives (heap spray is often used for exploitation but can show resource abuse)
  /\b(?:heap(?:[-\s]?spray)|allocation(?:[-\s]?bomb))\b/i
];

const clientSignalPatterns: RegExp[] = [
  /(client[- ]?side)/i,
  /(browser|chrome|firefox|edge|safari|webkit|internet explorer|msie|trident)/i,
  /(desktop|workstation|endpoint|reader|viewer|player)/i,
  /(local user|user interaction)/i
]

const clientApplicationPatterns: RegExp[] = [
  /(microsoft (?:office|word|excel|powerpoint|outlook|project|visio))/i,
  /(office (?:document|file))/i,
  /(mshtml|msdt|mshta|jscript|vbscript|activex|ole)/i,
  /(smart[- ]?screen|mark of the web|motw)/i,
  /(adobe (?:reader|acrobat))/i,
  /(winrar|7-zip|7zip|archive manager)/i,
  /(media (?:center|player)|windows media)/i,
  /(truetype|opentype|font (?:library|parsing|engine))/i
]

const clientFileInteractionPatterns: RegExp[] = [
  /(specially crafted|malicious)[\s\S]{0,80}(?:document|file|attachment|email|message|image|font|media|archive|spreadsheet|presentation)/i,
  /(open(?:ing)?|view(?:ing)?|preview(?:ing)?|load(?:ing)?|process(?:ing)?|pars(?:e|ing))[\s\S]{0,80}(?:document|file|attachment|email|message|image|font|media|archive|content)/i,
  /(delivered (?:via|through) email)/i,
  /(when (?:viewing|opening|loading))[\s\S]{0,80}\.(?:docx|doc|rtf|xls|xlsx|ppt|pptx|pdf|eml|msg|zip|rar|iso)/i
]

const clientUserInteractionPatterns: RegExp[] = [
  /(email attachment)/i,
  /(phishing (?:email|message))/i,
  /(social engineering)/i,
  /(requires user interaction|user must (?:open|click|interact))/i
]

const clientLocalExecutionPatterns: RegExp[] = [
  /(local attacker|locally authenticated|local user)/i,
  /(execute code in (?:kernel|user) mode)/i
]

const serverSignalPatterns: RegExp[] = [
  /(server|service|daemon|appliance|controller)/i,
  /(web[- ]?based management|management server|management interface)/i,
  /(remote service|http service|network service)/i,
  /(gateway|vpn|firewall|router|switch)/i
]

const clientDomainHints: ReadonlySet<KevDomainCategory> = new Set(['Browsers'])

const serverDomainHints: ReadonlySet<KevDomainCategory> = new Set([
  'Web Applications',
  'Web Servers',
  'Mail Servers',
  'Networking & VPN',
  'Industrial Control Systems',
  'Cloud & SaaS',
  'Virtualization & Containers',
  'Database & Storage',
  'Security Appliances'
])

const rcePatterns: RegExp[] = [
  ...remoteExecutionPatterns,
  ...codeExecutionPatterns
]

const vulnerabilityRules: Array<{
  category: KevVulnerabilityCategory
  patterns: RegExp[]
}> = [
  {
    category: 'Command Injection',
    patterns: [/(command injection|os command|system\(|shell command)/i]
  },
  {
    category: 'SQL Injection',
    patterns: [/(sql injection|blind sql|sqli)/i]
  },
  {
    category: 'Cross-Site Scripting',
    patterns: [/(cross-site scripting|xss)/i]
  },
  {
    category: 'Server-Side Request Forgery',
    patterns: [/(server-side request forgery|ssrf)/i]
  },
  {
    category: 'Directory Traversal',
    patterns: [/(directory traversal|path traversal|dot-dot)/i]
  },
  {
    category: 'Memory Corruption',
    patterns: memoryCorruptionPatterns
  },
  {
    category: 'Remote Code Execution',
    patterns: rcePatterns
  },
  {
    category: 'Authentication Bypass',
    patterns: [/(authentication bypass|bypass authentication|unauthenticated access|without authentication|authorization bypass)/i]
  },
  {
    category: 'Information Disclosure',
    patterns: [/(information disclosure|data leak|information leak|exposure|sensitive information)/i]
  },
  {
    category: 'Denial of Service',
    patterns: [/(denial of service|dos attack|service disruption|resource exhaustion|crash)/i]
  },
  {
    category: 'Logic Flaw',
    patterns: [/(logic flaw|business logic|improper validation|improper access control)/i]
  }
]

const normalise = (value: string) => value.toLowerCase()

const matchCategory = <T extends string>(
  text: string,
  rules: Array<{ category: T; patterns: RegExp[] }>,
  fallback: T
): T[] => {
  const found = new Set<T>()

  for (const rule of rules) {
    if (rule.patterns.some(pattern => pattern.test(text))) {
      found.add(rule.category)
    }
  }

  if (!found.size) {
    found.add(fallback)
  }

  return Array.from(found)
}

export const classifyDomainCategories = (
  entry: Pick<
    KevBaseEntry,
    'vendor' | 'product' | 'vulnerabilityName' | 'description' | 'cvssVector'
  >
): { categories: KevDomainCategory[]; internetExposed: boolean } => {
  const source = normalise(`${entry.vendor} ${entry.product}`)
  const context = normalise(`${entry.vulnerabilityName ?? ''} ${entry.description ?? ''}`)
  const text = `${source} ${context}`
  const categories = new Set(matchCategory(text, domainRules, 'Other'))

  const isBrowser = categories.has('Browsers') || matchesAny(source, webNegativePatterns)
  const isWebServer = categories.has('Web Servers') || matchesAny(source, webServerPatterns)
  const isWebProduct = matchesAny(source, webProductPatterns)
  const isWebDevice = matchesAny(source, webDevicePatterns)
  const hasWebIndicators = matchesAny(context, webIndicatorPatterns)
  const hasStrongWebSignal = matchesAny(context, webStrongContextPatterns)
  const deviceHasWebSignal = isWebDevice && matchesAny(context, webDeviceContextPatterns)
  const hasManagementSignal = matchesAny(context, webManagementPatterns)
  const hasApiSignal = matchesAny(context, webApiPatterns)
  const hasNonWebProductSignal =
    matchesAny(source, nonWebProductPatterns) || matchesAny(context, nonWebProductPatterns)
  const hasNonWebContextSignal = matchesAny(context, nonWebContextPatterns)
  const isMailServer = categories.has('Mail Servers')
  const isNetworkDevice = categories.has('Networking & VPN')
  const edgeStrongProduct = matchesAny(source, edgeStrongProductPatterns)
  const edgeSupportingProduct = matchesAny(source, edgeSupportingProductPatterns)
  const edgeContextSignal =
    matchesAny(context, edgeContextPatterns) ||
    hasStrongWebSignal ||
    hasManagementSignal ||
    hasApiSignal ||
    deviceHasWebSignal
  const edgePortalSignal = matchesAny(context, edgePortalPatterns)
  const edgeMailSignal = matchesAny(context, edgeMailPatterns)
  const remoteContextSignal = matchesAny(context, remoteContextPatterns)
  const remoteExecutionSignal =
    matchesAny(context, remoteExecutionPatterns) || matchesAny(context, codeExecutionPatterns)
  const cvssTraits = parseCvssVector(entry.cvssVector)
  const networkAttackVector = cvssTraits?.attackVector === 'N'
  const lowPrivileges = !cvssTraits?.privilegesRequired || cvssTraits.privilegesRequired === 'N'
  const noUserInteraction = !cvssTraits?.userInteraction || cvssTraits.userInteraction === 'N'

  const hasStandaloneWebIndicator =
    hasWebIndicators && !hasNonWebProductSignal && !hasNonWebContextSignal
  const hasCombinedWebIndicator =
    hasStandaloneWebIndicator ||
    (hasWebIndicators &&
      (hasStrongWebSignal ||
        hasManagementSignal ||
        hasApiSignal ||
        isWebProduct ||
        isWebDevice ||
        isMailServer ||
        isNetworkDevice))

  const baseWebSignals =
    isWebProduct ||
    hasStrongWebSignal ||
    hasManagementSignal ||
    hasApiSignal ||
    deviceHasWebSignal ||
    (hasWebIndicators &&
      (isWebProduct ||
        isWebDevice ||
        isMailServer ||
        isNetworkDevice ||
        hasManagementSignal ||
        hasApiSignal))

  const shouldTagWeb =
    ((!isBrowser && !isWebServer) && baseWebSignals) || hasCombinedWebIndicator

  const shouldPreferNonWeb =
    hasNonWebProductSignal ||
    (hasNonWebContextSignal &&
      !hasStrongWebSignal &&
      !hasManagementSignal &&
      !hasApiSignal &&
      !isWebProduct &&
      !deviceHasWebSignal &&
      !hasCombinedWebIndicator)

  const productLooksLikeServer = matchesAny(source, webServerPatterns)

  if (
    categories.has('Web Applications') &&
    categories.has('Web Servers') &&
    !productLooksLikeServer
  ) {
    categories.delete('Web Servers')
  }

  if (shouldPreferNonWeb) {
    categories.delete('Web Applications')
    categories.add('Non-Web Applications')
  } else if (shouldTagWeb) {
    categories.add('Web Applications')
  }

  if (categories.has('Web Applications')) {
    categories.delete('Non-Web Applications')
  } else if (categories.has('Web Servers') && !shouldPreferNonWeb) {
    categories.delete('Non-Web Applications')
  } else if (!shouldPreferNonWeb) {
    categories.add('Non-Web Applications')
  }

  if (categories.size > 1 && categories.has('Other')) {
    categories.delete('Other')
  }

  const domainEdgeSignal = internetEdgeDomainHints.some(category => categories.has(category))
  const productConfidence =
    (edgeStrongProduct ? 2 : 0) + (edgeSupportingProduct ? 1 : 0) + (domainEdgeSignal ? 1 : 0)
  const contextConfidence =
    (edgeContextSignal ? 1.5 : 0) + (edgePortalSignal ? 1 : 0) + (edgeMailSignal ? 1 : 0)
  const remoteConfidence =
    (networkAttackVector ? 1 : 0) +
    (remoteContextSignal ? 1 : 0) +
    (remoteExecutionSignal ? 0.5 : 0) +
    (lowPrivileges ? 0.5 : 0) +
    (noUserInteraction ? 0.5 : 0)

  const hasExposureContext =
    edgeContextSignal || edgePortalSignal || edgeMailSignal || remoteContextSignal || networkAttackVector
  const strongProductBackers = edgeStrongProduct || (edgeSupportingProduct && hasExposureContext) || domainEdgeSignal

  const internetExposed =
    strongProductBackers && hasExposureContext && productConfidence + contextConfidence + remoteConfidence >= 3.5

  if (internetExposed) {
    categories.add('Internet Edge')
  }

  return { categories: Array.from(categories), internetExposed }
}

export const classifyExploitLayers = (
  entry: {
    vulnerabilityName: string
    description: string
    cvssVector?: string | null
  },
  domainCategories: KevDomainCategory[]
): KevExploitLayer[] => {
  const text = normalise(`${entry.vulnerabilityName} ${entry.description}`)
  const layers = new Set<KevExploitLayer>()

  const cvssTraits = parseCvssVector(entry.cvssVector)
  const cvssSuggestsLocal =
    cvssTraits?.attackVector === 'L' || cvssTraits?.attackVector === 'P'
  const cvssSuggestsRemote =
    cvssTraits?.attackVector === 'N' || cvssTraits?.attackVector === 'A'
  const cvssRequiresUserInteraction = cvssTraits?.userInteraction === 'R'
  const cvssPreAuth = cvssTraits?.privilegesRequired === 'N'

  const hasPrivilegeSignal = privilegePatterns.some(pattern => pattern.test(text))

  if (hasPrivilegeSignal) {
    layers.add('Privilege Escalation')
  }

  const hasExplicitRemoteRce = matchesAny(text, remoteExecutionPatterns)
  const hasCodeExecutionSignal = matchesAny(text, codeExecutionPatterns)
  const hasRemoteContext =
    hasExplicitRemoteRce || matchesAny(text, remoteContextPatterns) || Boolean(cvssSuggestsRemote)

  const qualifiesForRce =
    hasExplicitRemoteRce || (hasCodeExecutionSignal && hasRemoteContext)

  const hasMemoryCorruption = memoryCorruptionPatterns.some(pattern => pattern.test(text))
  const hasDosSignal = matchesAny(text, denialOfServicePatterns)
  const hasClientSignal = matchesAny(text, clientSignalPatterns)
  const hasClientApplicationSignal = matchesAny(text, clientApplicationPatterns)
  const hasClientFileSignal = matchesAny(text, clientFileInteractionPatterns)
  const hasClientUserInteractionSignal =
    matchesAny(text, clientUserInteractionPatterns) || Boolean(cvssRequiresUserInteraction)
  const hasClientLocalExecutionSignal =
    matchesAny(text, clientLocalExecutionPatterns) || Boolean(cvssSuggestsLocal)
  const hasServerSignal = serverSignalPatterns.some(pattern => pattern.test(text))

  const domainSuggestsClient = domainCategories.some(category =>
    clientDomainHints.has(category)
  )
  const domainSuggestsServer = domainCategories.some(category =>
    serverDomainHints.has(category)
  )

  const clientScore =
    (hasClientSignal ? 2 : 0) +
    (hasClientApplicationSignal ? 2 : 0) +
    (hasClientFileSignal ? 2 : 0) +
    (hasClientUserInteractionSignal ? 1 : 0) +
    (hasClientLocalExecutionSignal ? 1 : 0) +
    (cvssSuggestsLocal ? 1 : 0) +
    (cvssRequiresUserInteraction ? 1 : 0) +
    (domainSuggestsClient ? 1 : 0)
  const serverScore =
    (hasServerSignal ? 2 : 0) +
    (cvssSuggestsRemote ? 1 : 0) +
    (cvssPreAuth ? 1 : 0) +
    (domainSuggestsServer ? 1 : 0)

  const determineSide = (): 'Client-side' | 'Server-side' => {
    if (clientScore > serverScore) {
      return 'Client-side'
    }

    if (serverScore > clientScore) {
      return 'Server-side'
    }

    if (hasClientFileSignal || hasClientApplicationSignal) {
      return 'Client-side'
    }

    if (domainSuggestsServer && !domainSuggestsClient) {
      return 'Server-side'
    }

    if (domainSuggestsClient && !domainSuggestsServer) {
      return 'Client-side'
    }

    if (cvssSuggestsRemote && !cvssSuggestsLocal) {
      return 'Server-side'
    }

    if (cvssSuggestsLocal && !cvssSuggestsRemote) {
      return 'Client-side'
    }

    if (cvssRequiresUserInteraction && !hasServerSignal) {
      return 'Client-side'
    }

    if (hasServerSignal && !hasClientSignal) {
      return 'Server-side'
    }

    if (hasClientSignal && !hasServerSignal) {
      return 'Client-side'
    }

    if (
      hasRemoteContext &&
      !hasClientSignal &&
      !hasClientApplicationSignal &&
      !hasClientFileSignal &&
      !hasClientUserInteractionSignal &&
      !hasClientLocalExecutionSignal
    ) {
      return 'Server-side'
    }

    return 'Client-side'
  }

  if (!qualifiesForRce) {
    if (hasDosSignal) {
      const dosSide = determineSide()
      layers.add(dosSide === 'Client-side' ? 'DoS · Client-side' : 'DoS · Server-side')
    }
    return Array.from(layers)
  }

  const side = determineSide()

  const labelMap: Record<
    'Client-side' | 'Server-side',
    { memory: KevExploitLayer; nonMemory: KevExploitLayer }
  > = {
    'Client-side': {
      memory: 'RCE · Client-side Memory Corruption',
      nonMemory: 'RCE · Client-side Non-memory'
    },
    'Server-side': {
      memory: 'RCE · Server-side Memory Corruption',
      nonMemory: 'RCE · Server-side Non-memory'
    }
  }

  const label = hasMemoryCorruption
    ? labelMap[side].memory
    : labelMap[side].nonMemory

  layers.add(label)

  if (hasDosSignal) {
    layers.add(side === 'Client-side' ? 'DoS · Client-side' : 'DoS · Server-side')
  }

  return Array.from(layers)
}

export const classifyVulnerabilityCategories = (entry: {
  vulnerabilityName: string
  description: string
}): KevVulnerabilityCategory[] => {
  const text = normalise(`${entry.vulnerabilityName} ${entry.description}`)
  const categories = matchCategory(text, vulnerabilityRules, 'Other')

  return categories
}

export const enrichEntry = (entry: KevBaseEntry): KevEntry => {
  const { categories: domainCategories, internetExposed } = classifyDomainCategories(entry)
  const exploitLayers = classifyExploitLayers(entry, domainCategories)
  const vulnerabilityCategories = classifyVulnerabilityCategories(entry)

  return {
    ...entry,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed
  }
}
