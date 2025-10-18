import type {
  KevDomainCategory,
  KevEntry,
  KevVulnerabilityCategory
} from '~/types'

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
    patterns: [/(browser|chrome|firefox|edge|safari|webkit|chromium|brave|opera)/i]
  },
  {
    category: 'Web Applications',
    patterns: [/(wordpress|drupal|joomla|magento|confluence|jira|sharepoint|portal|cms|web application|http server|apache tomcat|nginx|iis|owa|webmail|web server)/i]
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
    category: 'Privilege Escalation',
    patterns: [/(privilege escalation|elevation of privilege|gain[s]? administrative|gain[s]? root|eop)/i]
  },
  {
    category: 'Memory Corruption',
    patterns: [/(memory corruption|buffer overflow|heap overflow|stack overflow|out-of-bounds|use-after-free|dangling pointer|double free|overflow)/i]
  },
  {
    category: 'Remote Code Execution',
    patterns: [/(remote code execution|code execution|rce|arbitrary code)/i]
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

export const classifyDomainCategories = (entry: {
  vendor: string
  product: string
  vulnerabilityName?: string
  description?: string
}): KevDomainCategory[] => {
  const source = normalise(`${entry.vendor} ${entry.product}`)
  const context = normalise(`${entry.vulnerabilityName ?? ''} ${entry.description ?? ''}`)
  const text = `${source} ${context}`
  const categories = matchCategory(text, domainRules, 'Other')

  return categories
}

export const classifyVulnerabilityCategories = (entry: {
  vulnerabilityName: string
  description: string
}): KevVulnerabilityCategory[] => {
  const text = normalise(`${entry.vulnerabilityName} ${entry.description}`)
  const categories = matchCategory(text, vulnerabilityRules, 'Other')

  return categories
}

export const enrichEntry = (entry: KevEntry): KevEntry => {
  const domainCategories = classifyDomainCategories(entry)
  const vulnerabilityCategories = classifyVulnerabilityCategories(entry)

  return {
    ...entry,
    domainCategories,
    vulnerabilityCategories
  }
}
