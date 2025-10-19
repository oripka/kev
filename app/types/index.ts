export type Period = 'daily' | 'weekly' | 'monthly'

export type Range = {
  start: Date
  end: Date
}

export type CvssSeverity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical'

export type CatalogSource = 'kev' | 'enisa'

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
  | 'Internet Edge'
  | 'Other'

export type KevExploitLayer =
  | 'RCE · Client-side Memory Corruption'
  | 'RCE · Server-side Memory Corruption'
  | 'RCE · Client-side Non-memory'
  | 'RCE · Server-side Non-memory'
  | 'DoS · Client-side'
  | 'DoS · Server-side'
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
  id: string
  cveId: string
  sources: CatalogSource[]
  vendor: string
  vendorKey: string
  product: string
  productKey: string
  vulnerabilityName: string
  description: string
  requiredAction: string | null
  dateAdded: string
  dueDate: string | null
  ransomwareUse: string | null
  notes: string[]
  cwes: string[]
  cvssScore: number | null
  cvssVector: string | null
  cvssVersion: string | null
  cvssSeverity: CvssSeverity | null
  epssScore: number | null
  assigner: string | null
  datePublished: string | null
  dateUpdated: string | null
  exploitedSince: string | null
  sourceUrl: string | null
  references: string[]
  aliases: string[]
  domainCategories: KevDomainCategory[]
  exploitLayers: KevExploitLayer[]
  vulnerabilityCategories: KevVulnerabilityCategory[]
  internetExposed: boolean
}

export type KevEntrySummary = Pick<
  KevEntry,
  | 'id'
  | 'cveId'
  | 'sources'
  | 'vendor'
  | 'vendorKey'
  | 'product'
  | 'productKey'
  | 'vulnerabilityName'
  | 'description'
  | 'dateAdded'
  | 'ransomwareUse'
  | 'cvssScore'
  | 'cvssSeverity'
  | 'epssScore'
  | 'domainCategories'
  | 'exploitLayers'
  | 'vulnerabilityCategories'
  | 'internetExposed'
>

export type KevCountDatum = {
  key: string
  name: string
  count: number
  vendorKey?: string
  vendorName?: string
}

export type TrackedProduct = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
}

export type KevResponse = {
  updatedAt: string
  entries: KevEntrySummary[]
  counts: {
    domain: KevCountDatum[]
    exploit: KevCountDatum[]
    vulnerability: KevCountDatum[]
    vendor: KevCountDatum[]
    product: KevCountDatum[]
  }
  catalogBounds: {
    earliest: string | null
    latest: string | null
  }
}

export type ProductCatalogItem = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
  sources: CatalogSource[]
  kevCount: number
}

export type ProductCatalogResponse = {
  items: ProductCatalogItem[]
}

export type ImportPhase =
  | 'idle'
  | 'preparing'
  | 'fetchingCvss'
  | 'fetchingEnisa'
  | 'enriching'
  | 'saving'
  | 'savingEnisa'
  | 'complete'
  | 'error'

export type ImportProgress = {
  phase: ImportPhase
  completed: number
  total: number
  message: string
  startedAt: string | null
  updatedAt: string | null
  error: string | null
}

export type { KevFilterState } from './kev'
