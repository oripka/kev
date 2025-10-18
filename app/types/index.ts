export type Period = 'daily' | 'weekly' | 'monthly'

export type Range = {
  start: Date
  end: Date
}

export type KevDomainCategory =
  | 'Web Applications'
  | 'Web Servers'
  | 'Non-Web Applications'
  | 'Mail Servers'
  | 'Browsers'
  | 'Operating Systems'
  | 'Networking & VPN'
  | 'Industrial Control Systems'
  | 'Cloud & SaaS'
  | 'Virtualization & Containers'
  | 'Database & Storage'
  | 'Security Appliances'
  | 'Other'

export type KevExploitLayer =
  | 'RCE · Client-side Memory Corruption'
  | 'RCE · Server-side Memory Corruption'
  | 'RCE · Client-side Non-memory'
  | 'RCE · Server-side Non-memory'
  | 'Privilege Escalation'

export type KevVulnerabilityCategory =
  | 'Remote Code Execution'
  | 'Memory Corruption'
  | 'Command Injection'
  | 'Authentication Bypass'
  | 'Information Disclosure'
  | 'Denial of Service'
  | 'Directory Traversal'
  | 'SQL Injection'
  | 'Cross-Site Scripting'
  | 'Server-Side Request Forgery'
  | 'Logic Flaw'
  | 'Other'

export type KevEntry = {
  cveId: string
  vendor: string
  product: string
  vulnerabilityName: string
  description: string
  requiredAction: string
  dateAdded: string
  dueDate: string | null
  ransomwareUse: string | null
  notes: string[]
  cwes: string[]
  domainCategories: KevDomainCategory[]
  exploitLayers: KevExploitLayer[]
  vulnerabilityCategories: KevVulnerabilityCategory[]
}

export type KevResponse = {
  updatedAt: string
  entries: KevEntry[]
}

export type { KevFilterState } from './kev'
