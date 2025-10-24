import { load, type CheerioAPI, type Element } from 'cheerio'
import { ofetch } from 'ofetch'
import { matchExploitProduct } from '~/utils/exploitProductHints'
import { matchVendorProductByTitle } from '../../utils/metasploitVendorCatalog'
import { createCategory, defaultHeaders, normaliseWhitespace, parseRewardRange, stripHtml } from '../utils'
import type { MarketOfferInput, MarketProgramDefinition } from '../types'

const CROWDFENSE_URL = 'https://www.crowdfense.com/exploit-acquisition-program/'

const findNearestHeading = ($: CheerioAPI, element: Element): string | null => {
  let current: Element | null = element
  while (current) {
    const prevSiblings = $(current).prevAll().toArray()
    for (const sibling of prevSiblings) {
      const tag = sibling.tagName?.toLowerCase()
      if (tag && /^h[1-6]$/.test(tag)) {
        const text = stripHtml($(sibling).html() ?? '')
        if (text) {
          return text
        }
      }
    }
    const parent = $(current).parent().get(0)
    if (!parent || $(parent).hasClass('tab-pane') || parent.tagName?.toLowerCase() === 'body') {
      break
    }
    current = parent
  }
  return null
}

const parseOffers = async (html: string, fetchedAt: string): Promise<MarketOfferInput[]> => {
  const $ = load(html)
  const tabLabels = new Map<string, string>()
  $('.tabs .nav a').each((_, element) => {
    const href = $(element).attr('href')
    const id = href?.replace(/^#/, '')
    const label = stripHtml($(element).html() ?? '')
    if (id && label) {
      tabLabels.set(id, label)
    }
  })

  const offers: MarketOfferInput[] = []

  $('.tab-pane').each((_, pane) => {
    const tabId = $(pane).attr('id') ?? ''
    const scopeLabel = tabLabels.get(tabId) ?? 'General scope'
    $(pane)
      .find('li')
      .each((_, item) => {
        const strong = $(item).find('strong').first()
        if (!strong.length) {
          return
        }
        const strongText = stripHtml(strong.html() ?? '')
        if (!strongText) {
          return
        }

        const listClone = $(item).clone()
        listClone.find('ul').remove()
        const fullText = stripHtml(listClone.html() ?? '')
        const reward = parseRewardRange(fullText)
        if (!reward) {
          return
        }

        const heading = findNearestHeading($, item)
        const categories = [createCategory('scope', scopeLabel)]
        if (heading) {
          categories.push(createCategory('category', heading))
        }

        const cleanTitle = strongText.replace(/[:\-]+\s*$/u, '')
        const description = normaliseWhitespace(fullText.replace(strongText, '').replace(/^[:\-\s]+/, '')) || null
        const hint = matchExploitProduct(strongText)
        const catalogHint = matchVendorProductByTitle([strongText, heading, scopeLabel])
        const baseProduct = strongText.replace(/\([^)]*\)/g, '').replace(/[:\-]+\s*$/u, '').trim()
        const targetProduct = hint?.product ?? catalogHint?.product ?? baseProduct
        const targetVendor = hint?.vendor ?? catalogHint?.vendor ?? null

        const rewardType =
          reward.min !== null && reward.max !== null && reward.min !== reward.max ? 'range' : 'flat'

        offers.push({
          title: cleanTitle || strongText,
          description,
          minReward: reward.min !== null ? { amount: reward.min, currency: reward.currency ?? 'USD' } : null,
          maxReward: reward.max !== null ? { amount: reward.max, currency: reward.currency ?? 'USD' } : null,
          currency: reward.currency ?? 'USD',
          rewardType,
          exclusivity: /exclusive/i.test(scopeLabel) ? 'exclusive' : null,
          sourceUrl: CROWDFENSE_URL,
          sourceCaptureDate: fetchedAt,
          categories,
          targets: [
            {
              vendor: targetVendor,
              product: targetProduct || cleanTitle,
              rawText: strongText
            }
          ]
        })
      })
  })

  return offers
}

export const crowdfenseProgram: MarketProgramDefinition = {
  slug: 'crowdfense',
  name: 'Crowdfense Exploit Acquisition Program',
  operator: 'Crowdfense',
  programType: 'exploit-broker',
  homepageUrl: CROWDFENSE_URL,
  scrapeFrequency: 'weekly',
  parserVersion: '2025-02-15',
  fetchSnapshot: async () => {
    const raw = await ofetch<string>(CROWDFENSE_URL, { headers: defaultHeaders })
    return {
      url: CROWDFENSE_URL,
      raw,
      fetchedAt: new Date().toISOString(),
      contentType: 'html'
    }
  },
  parseOffers: async snapshot => parseOffers(snapshot.raw, snapshot.fetchedAt)
}
