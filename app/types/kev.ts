export interface KevEntry {
  cveId: string
  vendor: string
  product: string
  vulnerability: string
  vulnerabilityType: string
  category: string
  dateAdded: string
  dueDate: string | null
  requiredAction: string
  shortDescription: string
  knownRansomware: boolean
  sources: string[]
  cwes: string[]
}

export interface KevFeedResponse {
  title: string
  catalogVersion: string
  dateReleased: string
  fetchedAt: string
  count: number
  entries: KevEntry[]
}

export interface KevFilterState {
  search: string
  vendor: string | null
  product: string | null
  category: string | null
  vulnerabilityType: string | null
  ransomwareOnly: boolean
  startDate: string | null
  endDate: string | null
}
