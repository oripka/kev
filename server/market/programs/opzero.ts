import { load } from 'cheerio'
import { ofetch } from 'ofetch'
import {
  MARKET_FETCH_TIMEOUT_MS,
  createCategory,
  defaultHeaders,
  normaliseWhitespace,
  parseRewardRange,
  stripHtml
} from '../utils'
import type { MarketOfferInput, MarketProgramDefinition } from '../types'

const OPZERO_URL = 'https://opzero.ru/en/prices/'

const parseOffers = (html: string, fetchedAt: string): MarketOfferInput[] => {
  const $ = load(html)
  const offers: MarketOfferInput[] = []

  $('.price-card').each((_, card) => {
    const cardScope = stripHtml($(card).find('.price-card__main .title_size_h6').first().html() ?? '')
    $(card)
      .find('.price-card__item')
      .each((_, item) => {
        const name = stripHtml($(item).find('.price-card__item-name').html() ?? '')
        const priceText = stripHtml($(item).find('.price-card__price').html() ?? '')
        if (!name || !priceText) {
          return
        }
        const reward = parseRewardRange(priceText)
        if (!reward) {
          return
        }
        const categories = cardScope ? [createCategory('scope', cardScope)] : []
        const rewardType =
          reward.min !== null && reward.max !== null && reward.min !== reward.max ? 'range' : 'flat'

        offers.push({
          title: name,
          description: normaliseWhitespace(priceText),
          minReward: reward.min !== null ? { amount: reward.min, currency: reward.currency ?? 'USD' } : null,
          maxReward: reward.max !== null ? { amount: reward.max, currency: reward.currency ?? 'USD' } : null,
          currency: reward.currency ?? 'USD',
          rewardType,
          sourceUrl: OPZERO_URL,
          sourceCaptureDate: fetchedAt,
          categories,
          targets: [
            {
              product: name,
              rawText: name
            }
          ]
        })
      })
  })

  return offers
}

export const opzeroProgram: MarketProgramDefinition = {
  slug: 'opzero',
  name: 'Operation Zero Exploit Acquisition',
  operator: 'Operation Zero',
  programType: 'exploit-broker',
  homepageUrl: OPZERO_URL,
  scrapeFrequency: 'weekly',
  parserVersion: '2025-02-15',
  fetchSnapshot: async () => {
    const raw = await ofetch<string>(OPZERO_URL, {
      headers: defaultHeaders,
      timeout: MARKET_FETCH_TIMEOUT_MS
    })
    return {
      url: OPZERO_URL,
      raw,
      fetchedAt: new Date().toISOString(),
      contentType: 'html'
    }
  },
  parseOffers: async snapshot => parseOffers(snapshot.raw, snapshot.fetchedAt)
}
