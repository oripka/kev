import type { CatalogSource } from '~/types'

export type MarketProgramType = 'exploit-broker' | 'bug-bounty' | 'other'

export type MarketProgramSnapshot = {
  url: string
  raw: string
  fetchedAt: string
  contentType: 'html' | 'json'
}

export type RewardAmount = {
  amount: number
  currency: string
}

export type MarketOfferCategoryInput = {
  type: string
  key: string
  name: string
}

export type MarketOfferTargetInput = {
  vendor?: string | null
  product?: string | null
  cveId?: string | null
  confidence?: number | null
  matchMethod?: 'exact' | 'fuzzy' | 'manual-review'
  rawText?: string | null
  sourceHint?: CatalogSource
}

export type MarketOfferInput = {
  title: string
  description?: string | null
  minReward?: RewardAmount | null
  maxReward?: RewardAmount | null
  currency?: string | null
  rewardType?: 'flat' | 'range' | 'bounty' | 'bonus'
  exclusivity?: string | null
  sourceUrl: string
  sourceCaptureDate?: string | null
  effectiveStart?: string | null
  effectiveEnd?: string | null
  cveIds?: string[]
  categories?: MarketOfferCategoryInput[]
  targets: MarketOfferTargetInput[]
  notes?: string | null
}

export type MarketProgramDefinition = {
  slug: string
  name: string
  operator: string
  programType: MarketProgramType
  homepageUrl: string
  scrapeFrequency: string
  description?: string
  parserVersion: string
  fetchSnapshot: () => Promise<MarketProgramSnapshot>
  parseOffers: (snapshot: MarketProgramSnapshot) => Promise<MarketOfferInput[]>
}

export type MarketProgramProgress = {
  program: MarketProgramDefinition
  offersProcessed: number
}
