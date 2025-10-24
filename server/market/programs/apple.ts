import { ofetch } from 'ofetch'
import { matchExploitProduct } from '~/utils/exploitProductHints'
import { matchVendorProductByTitle } from '../../utils/metasploitVendorCatalog'
import { createCategory, defaultHeaders, normaliseWhitespace } from '../utils'
import type { MarketOfferInput, MarketProgramDefinition } from '../types'

const APPLE_URL = 'https://security.apple.com/bounty/categories/'

type NextData = {
  props?: {
    pageProps?: {
      data?: {
        ProductTable?: Array<{ title: string; topics: AppleTopic[] }>
        ServicesTable?: Array<{ title: string; topics: AppleTopic[] }>
      }
    }
  }
}

type AppleTopic = {
  topic: string
  min?: number | null
  max?: number | null
  amount?: string
  examples?: { code?: string }
}

const extractNextData = (html: string): NextData | null => {
  const marker = 'id="__NEXT_DATA__"'
  const index = html.indexOf(marker)
  if (index === -1) {
    return null
  }
  const scriptStart = html.lastIndexOf('<script', index)
  const scriptEnd = html.indexOf('</script>', index)
  if (scriptStart === -1 || scriptEnd === -1) {
    return null
  }
  const raw = html.slice(scriptStart, scriptEnd)
  const jsonStart = raw.indexOf('>') + 1
  const json = raw.slice(jsonStart)
  try {
    return JSON.parse(json) as NextData
  } catch {
    return null
  }
}

const parseTopics = (
  entries: Array<{ title: string; topics: AppleTopic[] }> | undefined,
  fetchedAt: string
): MarketOfferInput[] => {
  if (!entries?.length) {
    return []
  }
  const offers: MarketOfferInput[] = []

  for (const entry of entries) {
    const scopeCategory = createCategory('scope', entry.title)
    for (const topic of entry.topics ?? []) {
      const title = topic.topic?.trim()
      if (!title) {
        continue
      }
      const min = typeof topic.min === 'number' ? topic.min : null
      const max = typeof topic.max === 'number' ? topic.max : null
      const rewardType = min !== null && max !== null && min !== max ? 'range' : 'flat'
      const description = topic.amount ? normaliseWhitespace(topic.amount) : null
      const hint = matchExploitProduct(title)
      const catalogHint = matchVendorProductByTitle([title, entry.title])
      const fallbackProduct = `${entry.title} - ${title}`
      const categories = [scopeCategory, createCategory('program', 'Apple Security Bounty')]

      offers.push({
        title,
        description,
        minReward: min !== null ? { amount: min, currency: 'USD' } : null,
        maxReward: max !== null ? { amount: max, currency: 'USD' } : null,
        currency: 'USD',
        rewardType,
        sourceUrl: APPLE_URL,
        sourceCaptureDate: fetchedAt,
        categories,
        targets: [
          {
            vendor: hint?.vendor ?? catalogHint?.vendor ?? 'Apple',
            product: hint?.product ?? catalogHint?.product ?? fallbackProduct,
            rawText: title
          }
        ]
      })
    }
  }

  return offers
}

const parseOffers = (html: string, fetchedAt: string): MarketOfferInput[] => {
  const data = extractNextData(html)
  if (!data?.props?.pageProps?.data) {
    return []
  }
  const productOffers = parseTopics(data.props.pageProps.data.ProductTable, fetchedAt)
  const serviceOffers = parseTopics(data.props.pageProps.data.ServicesTable, fetchedAt)
  return [...productOffers, ...serviceOffers]
}

export const appleProgram: MarketProgramDefinition = {
  slug: 'apple-security-bounty',
  name: 'Apple Security Bounty',
  operator: 'Apple',
  programType: 'bug-bounty',
  homepageUrl: APPLE_URL,
  scrapeFrequency: 'monthly',
  parserVersion: '2025-02-15',
  fetchSnapshot: async () => {
    const raw = await ofetch<string>(APPLE_URL, { headers: defaultHeaders })
    return {
      url: APPLE_URL,
      raw,
      fetchedAt: new Date().toISOString(),
      contentType: 'html'
    }
  },
  parseOffers: async snapshot => parseOffers(snapshot.raw, snapshot.fetchedAt)
}
