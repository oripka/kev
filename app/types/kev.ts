export interface KevFilterState {
  search: string
  cvssRange: [number, number] | null
  epssRange: [number, number] | null
  vendor: string | null
  product: string | null
  category: string | null
  exploitLayer: string | null
  vulnerabilityType: string | null
  ransomwareOnly: boolean
  wellKnownOnly: boolean
  source: 'all' | 'kev' | 'enisa'
  startDate: string | null
  endDate: string | null
}
