export interface KevFilterState {
  search: string
  cvssRange: [number, number] | null
  vendor: string | null
  product: string | null
  category: string | null
  exploitLayer: string | null
  vulnerabilityType: string | null
  ransomwareOnly: boolean
  wellKnownOnly: boolean
  startDate: string | null
  endDate: string | null
}
