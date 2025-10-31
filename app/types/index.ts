export type Period = 'daily' | 'weekly' | 'monthly'

export type Range = {
  start: Date
  end: Date
}

export type CvssSeverity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical'

export type CatalogSource =
  | 'kev'
  | 'enisa'
  | 'historic'
  | 'custom'
  | 'metasploit'
  | 'poc'
  | 'market'

export type MarketProgramType = 'exploit-broker' | 'bug-bounty' | 'other'

export type MarketCategory = {
  type: string
  name: string
}

export type MarketSignal = {
  offerCount: number
  minRewardUsd: number | null
  maxRewardUsd: number | null
  averageRewardUsd: number | null
  lastSeenAt: string | null
  programTypes: MarketProgramType[]
  categories: MarketCategory[]
}

export type KevTimelineEventType =
  | 'cve_published'
  | 'kev_listed'
  | 'enisa_listed'
  | 'metasploit_module'
  | 'poc_published'
  | 'historic_reference'
  | 'exploitation_observed'
  | 'custom'

export type KevEntryTimelineEvent = {
  id: string
  timestamp: string
  type: KevTimelineEventType
  source?: 'nvd' | CatalogSource
  title?: string
  description?: string
  metadata?: Record<string, string | number | boolean | null>
  url?: string | null
  icon?: string | null
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
  | 'Internet Edge'
  | 'Other'

export type KevExploitLayer =
  | 'RCE · Client-side Memory Corruption'
  | 'RCE · Server-side Memory Corruption'
  | 'RCE · Client-side Non-memory'
  | 'RCE · Server-side Non-memory'
  | 'DoS · Client-side'
  | 'DoS · Server-side'
  | 'Mixed/Needs Review'
  | 'Auth Bypass · Edge'
  | 'Auth Bypass · Server-side'
  | 'Configuration Abuse'
  | 'Privilege Escalation'
  | 'Command Injection'

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
  affectedProducts: KevAffectedProduct[]
  problemTypes: KevProblemType[]
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
  pocUrl: string | null
  pocPublishedAt: string | null
  references: string[]
  aliases: string[]
  metasploitModulePath: string | null
  metasploitModulePublishedAt: string | null
  domainCategories: KevDomainCategory[]
  exploitLayers: KevExploitLayer[]
  vulnerabilityCategories: KevVulnerabilityCategory[]
  internetExposed: boolean
  marketSignals: MarketSignal | null
}

export type KevProblemType = {
  cweId?: string
  description: string
  source: 'cna' | 'adp'
}

export type KevVersionRange = {
  version?: string | null
  introduced?: string | null
  fixed?: string | null
  lessThan?: string | null
  lessThanOrEqual?: string | null
  greaterThan?: string | null
  greaterThanOrEqual?: string | null
  status?: string | null
  versionType?: string | null
}

export type KevAffectedProduct = {
  vendor: string
  vendorKey: string
  product: string
  productKey: string
  status?: string | null
  source: 'cna' | 'adp' | 'cpe'
  platforms: string[]
  versions: KevVersionRange[]
}

export type KevEntryDetail = KevEntry & {
  timeline: KevEntryTimelineEvent[]
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
  | 'dueDate'
  | 'dateAdded'
  | 'datePublished'
  | 'ransomwareUse'
  | 'cvssScore'
  | 'cvssSeverity'
  | 'epssScore'
  | 'domainCategories'
  | 'exploitLayers'
  | 'vulnerabilityCategories'
  | 'internetExposed'
  | 'aliases'
  | 'marketSignals'
  | 'pocPublishedAt'

export type KevCountDatum = {
  key: string
  name: string
  count: number
  vendorKey?: string
  vendorName?: string
}

export type KevTimelineBucket = {
  date: string
  count: number
}

export type KevTimeline = {
  range: { start: string; end: string } | null
  buckets: Record<Period, KevTimelineBucket[]>
}

export type KevHeatmapGroups = {
  vendor: KevCountDatum[]
  product: KevCountDatum[]
}

export type MarketCategoryDatum = {
  key: string
  name: string
  categoryType: string
  count: number
}

export type TrackedProduct = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
}

export type TrackedProductQuickFilterTarget = {
  product: TrackedProduct
  latestAddedAt: string | null
  recentWindowDays: number | null
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
  heatmap: KevHeatmapGroups
  catalogBounds: {
    earliest: string | null
    latest: string | null
  }
  timeline: KevTimeline
  totalEntries: number
  totalEntriesWithoutYear: number
  entryLimit: number
  market: MarketOverview
}

export type MarketOverview = {
  priceBounds: { minRewardUsd: number | null; maxRewardUsd: number | null }
  filteredPriceBounds: { minRewardUsd: number | null; maxRewardUsd: number | null }
  offerCount: number
  programCounts: KevCountDatum[]
  categoryCounts: MarketCategoryDatum[]
}

export type ProductCatalogItem = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
  sources: CatalogSource[]
  matchCount: number
}

export type ProductCatalogResponse = {
  items: ProductCatalogItem[]
}

export type MarketOfferSummary = {
  id: string
  title: string
  programName: string
  programType: MarketProgramType
  minRewardUsd: number | null
  maxRewardUsd: number | null
  averageRewardUsd: number | null
  sourceUrl: string
  sourceCaptureDate: string | null
  productNames: string[]
  vendorNames: string[]
  targetSummaries: string[]
}

export type MarketOfferTargetMatchMethod = 'exact' | 'fuzzy' | 'manual-review' | 'unknown'

export type MarketOfferTargetMatch = {
  cveId: string
  vulnerabilityName: string
  vendorName: string
  vendorKey: string
  productName: string
  productKey: string
  domainCategories: KevDomainCategory[]
  exploitLayers: KevExploitLayer[]
  vulnerabilityCategories: KevVulnerabilityCategory[]
  cvssScore: number | null
  cvssSeverity: CvssSeverity | null
  cvssVector: string | null
}

export type MarketOfferTarget = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
  cveId: string | null
  confidence: number | null
  matchMethod: MarketOfferTargetMatchMethod
  matches: MarketOfferTargetMatch[]
}

export type MarketOfferCategoryTag = {
  type: string
  key: string
  name: string
}

export type MarketOfferListItem = {
  id: string
  title: string
  description: string | null
  programName: string
  programType: MarketProgramType
  minRewardUsd: number | null
  maxRewardUsd: number | null
  averageRewardUsd: number | null
  sourceUrl: string
  sourceCaptureDate: string
  exclusivity: string | null
  targets: MarketOfferTarget[]
  categories: MarketOfferCategoryTag[]
  matchedCveIds: string[]
  matchedKevCveIds: string[]
}

export type MarketStatsResponse = {
  totals: {
    offerCount: number
    programCount: number
    averageRewardUsd: number | null
    minRewardUsd: number | null
    maxRewardUsd: number | null
    lastSeenAt: string | null
  }
  programCounts: KevCountDatum[]
  categoryCounts: MarketCategoryDatum[]
  topOffers: MarketOfferSummary[]
}

export type MarketOffersResponse = {
  items: MarketOfferListItem[]
  total: number
  page: number
  pageSize: number
}

export type ImportPhase =
  | 'idle'
  | 'preparing'
  | 'fetchingCvss'
  | 'fetchingEnisa'
  | 'fetchingEpss'
  | 'fetchingHistoric'
  | 'fetchingCustom'
  | 'fetchingMetasploit'
  | 'fetchingPoc'
  | 'fetchingMarket'
  | 'enriching'
  | 'resolvingPocHistory'
  | 'saving'
  | 'savingEnisa'
  | 'savingEpss'
  | 'savingHistoric'
  | 'savingCustom'
  | 'savingMetasploit'
  | 'savingPoc'
  | 'savingMarket'
  | 'complete'
  | 'error'

export type ImportTaskKey = CatalogSource | 'market' | 'epss'

export type ImportTaskStatus = 'pending' | 'running' | 'complete' | 'skipped' | 'error'

export type ImportTaskProgress = {
  key: ImportTaskKey
  label: string
  status: ImportTaskStatus
  message: string
  completed: number
  total: number
}

export type ImportProgressEventStatus = ImportTaskStatus | 'info'

export type ImportProgressEvent = {
  id: string
  timestamp: string
  status: ImportProgressEventStatus
  message: string
  taskKey: ImportTaskKey | null
  taskLabel: string | null
  phase: ImportPhase | null
}

export type ImportProgress = {
  phase: ImportPhase
  completed: number
  total: number
  message: string
  startedAt: string | null
  updatedAt: string | null
  error: string | null
  activeSources: ImportTaskKey[]
  tasks: ImportTaskProgress[]
  events: ImportProgressEvent[]
}

export type ClassificationPhase = 'idle' | 'preparing' | 'rebuilding' | 'complete' | 'error'

export type ClassificationProgress = {
  phase: ClassificationPhase
  completed: number
  total: number
  message: string
  startedAt: string | null
  updatedAt: string | null
  error: string | null
}

export type ClassificationReviewFilterContext = {
  key: string
  label: string
  value: string
}

export type ClassificationReviewRequestContext = {
  matchingResultsLabel?: string
  activeFilters?: ClassificationReviewFilterContext[]
}

export type ClassificationReviewConfidence = 'low' | 'medium' | 'high'

export type ClassificationReviewCategorySet = {
  domain?: KevDomainCategory[]
  exploit?: KevExploitLayer[]
  vulnerability?: KevVulnerabilityCategory[]
  internetExposed?: boolean | null
}

export type ClassificationReviewIssue = {
  cveId: string
  summary: string
  suspectedIssues: string[]
  recommendedCategories: ClassificationReviewCategorySet | null
  justification: string
  confidence: ClassificationReviewConfidence
}

export type ClassificationReviewTaxonomySuggestion = {
  vendorKey: string | null
  productKey: string
  proposedCategories: KevDomainCategory[]
  proposedAddCategories: KevDomainCategory[]
  internetExposed?: boolean | null
  serverBias?: boolean | null
  clientBias?: boolean | null
  rationale: string
}

export type ClassificationReviewHeuristicIdea = {
  focusArea: string
  description: string
  justification: string
}

export type ClassificationReviewOverview = {
  totalEntries: number
  domainCounts: Array<{ value: KevDomainCategory; count: number; share: number }>
  exploitCounts: Array<{ value: KevExploitLayer; count: number; share: number }>
  vulnerabilityCounts: Array<{ value: KevVulnerabilityCategory; count: number; share: number }>
  internetExposure: { exposed: number; total: number }
  sources: CatalogSource[]
}

export type ClassificationReviewSuccess = {
  status: 'ok'
  model: string
  usedEntryIds: string[]
  missingEntryIds?: string[]
  issues: ClassificationReviewIssue[]
  taxonomySuggestions: ClassificationReviewTaxonomySuggestion[]
  heuristicImprovements: ClassificationReviewHeuristicIdea[]
  generalRecommendations: string[]
  overview: ClassificationReviewOverview
  rawResponseSnippet?: string
  usage?: { promptTokens?: number; completionTokens?: number; totalTokens?: number }
}

export type ClassificationReviewError = {
  status: 'error'
  message: string
  code?: string
  details?: string
}

export type ClassificationReviewResponse =
  | ClassificationReviewSuccess
  | ClassificationReviewError

export type { KevFilterState } from './kev'
