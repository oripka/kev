import { createHash } from 'node:crypto'
import { ofetch } from 'ofetch'
import type { MarketOfferCategoryInput } from './types'

type ExchangeRates = Map<string, number>

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'

export const MARKET_FETCH_TIMEOUT_MS = 15_000

const HTML_ENTITY_MAP: Record<string, string> = {
  '&nbsp;': ' ',
  '&amp;': '&',
  '&quot;': '"',
  '&#39;': "'",
  '&apos;': "'",
  '&lt;': '<',
  '&gt;': '>'
}

export const defaultHeaders = {
  'user-agent': USER_AGENT,
  'accept-language': 'en-US,en;q=0.9'
}

export const decodeHtmlEntities = (value: string): string =>
  value
    .replace(/&#(\d+);/g, (_, code) => {
      const charCode = Number.parseInt(code, 10)
      return Number.isFinite(charCode) ? String.fromCharCode(charCode) : ''
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      const charCode = Number.parseInt(hex, 16)
      return Number.isFinite(charCode) ? String.fromCharCode(charCode) : ''
    })
    .replace(/&(nbsp|amp|quot|lt|gt|apos);/gi, match => HTML_ENTITY_MAP[match.toLowerCase()] ?? '')

export const stripHtml = (value: string): string => {
  const withoutTags = value.replace(/<[^>]*>/g, ' ')
  return decodeHtmlEntities(withoutTags).replace(/\s+/g, ' ').trim()
}

export const normaliseWhitespace = (value: string): string => value.replace(/\s+/g, ' ').trim()

export const slugifyLabel = (value: string): string => {
  const trimmed = value.trim().toLowerCase()
  const slug = trimmed
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return slug || 'unknown'
}

type RewardParseResult = {
  min: number | null
  max: number | null
  currency: string | null
}

const normaliseNumberFragment = (fragment: string): number | null => {
  const trimmed = fragment.trim()
  if (!trimmed) {
    return null
  }
  const hasComma = trimmed.includes(',')
  const hasDot = trimmed.includes('.')
  let normalised = trimmed
  if (hasComma && hasDot) {
    normalised = normalised.replace(/,/g, '')
  } else if (hasComma && !hasDot) {
    const [, fractional] = normalised.split(',')
    if (fractional && fractional.length <= 2) {
      normalised = normalised.replace(',', '.')
    } else {
      normalised = normalised.replace(/,/g, '')
    }
  }
  const parsed = Number.parseFloat(normalised)
  return Number.isFinite(parsed) ? parsed : null
}

const detectCurrencyFromText = (value: string): string | null => {
  if (/usd|\$/i.test(value)) {
    return 'USD'
  }
  if (/eur|€/.test(value)) {
    return 'EUR'
  }
  if (/gbp|£/.test(value)) {
    return 'GBP'
  }
  return null
}

export const parseRewardRange = (value: string): RewardParseResult | null => {
  const currency = detectCurrencyFromText(value) ?? null
  const matches = value.matchAll(/(\d[\d.,]*)\s*(m|million|k|thousand|b|billion)?/gi)
  const numbers: number[] = []
  for (const match of matches) {
    const [, numericPart, suffixRaw] = match
    if (!numericPart) {
      continue
    }
    const baseValue = normaliseNumberFragment(numericPart)
    if (baseValue === null) {
      continue
    }
    const suffix = suffixRaw?.toLowerCase() ?? ''
    const multiplier = suffix.startsWith('b') ? 1_000_000_000 : suffix.startsWith('m') ? 1_000_000 : suffix.startsWith('k') || suffix.includes('thousand') ? 1_000 : 1
    numbers.push(baseValue * multiplier)
  }
  if (!numbers.length) {
    return null
  }
  const min = Math.min(...numbers)
  const max = Math.max(...numbers)
  return { min, max, currency }
}

export const createCategory = (type: string, name: string): MarketOfferCategoryInput => ({
  type,
  key: slugifyLabel(name),
  name: normaliseWhitespace(name)
})

const EXCHANGE_ENDPOINT = 'https://open.er-api.com/v6/latest/USD'

export const fetchUsdExchangeRates = async (): Promise<ExchangeRates> => {
  try {
    const response = await ofetch<{ rates?: Record<string, number> }>(EXCHANGE_ENDPOINT, {
      headers: defaultHeaders,
      timeout: Math.min(MARKET_FETCH_TIMEOUT_MS, 7_000)
    })
    const rates = new Map<string, number>()
    rates.set('USD', 1)
    if (response?.rates) {
      for (const [code, rate] of Object.entries(response.rates)) {
        if (typeof rate === 'number' && Number.isFinite(rate)) {
          rates.set(code.toUpperCase(), rate)
        }
      }
    }
    return rates
  } catch {
    const fallback = new Map<string, number>()
    fallback.set('USD', 1)
    fallback.set('EUR', 0.9)
    fallback.set('GBP', 0.8)
    return fallback
  }
}

const normaliseCurrencyCode = (value: string | null | undefined): string => {
  if (!value) {
    return 'USD'
  }
  const upper = value.toUpperCase()
  if (upper === '$') {
    return 'USD'
  }
  return upper
}

export const convertAmountToUsd = (
  amount: number | null | undefined,
  currency: string | null | undefined,
  rates: ExchangeRates
): number | null => {
  if (typeof amount !== 'number' || !Number.isFinite(amount)) {
    return null
  }
  const code = normaliseCurrencyCode(currency)
  if (code === 'USD') {
    return amount
  }
  const rate = rates.get(code)
  if (!rate || rate === 0) {
    return null
  }
  return amount / rate
}

export const differenceInDays = (from: Date, to: Date): number => {
  const diff = to.getTime() - from.getTime()
  return diff / (1000 * 60 * 60 * 24)
}

type ValuationInput = {
  minRewardUsd: number | null
  maxRewardUsd: number | null
  exclusivity?: string | null
  sourceCaptureDate?: string | null
}

type ValuationResult = {
  score: number
  breakdown: {
    priceComponent: number
    exclusivityBonus: number
    freshnessPenalty: number
  }
}

export const computeValuationScore = ({
  minRewardUsd,
  maxRewardUsd,
  exclusivity,
  sourceCaptureDate
}: ValuationInput): ValuationResult => {
  const now = new Date()
  const amounts = [minRewardUsd, maxRewardUsd].filter(
    (value): value is number => typeof value === 'number' && Number.isFinite(value)
  )
  const representative = amounts.length
    ? amounts.reduce((sum, value) => sum + value, 0) / amounts.length
    : 0
  const priceComponent = representative > 0 ? Math.log10(representative + 1) * 20 : 0
  const exclusivityBonus = exclusivity && /exclusive/i.test(exclusivity) ? 10 : 0
  let freshnessPenalty = 0
  if (sourceCaptureDate) {
    const capture = new Date(sourceCaptureDate)
    if (!Number.isNaN(capture.getTime())) {
      const ageDays = Math.max(0, differenceInDays(capture, now))
      freshnessPenalty = ageDays * 0.1
    }
  }
  const score = Math.max(0, priceComponent + exclusivityBonus - freshnessPenalty)
  return {
    score,
    breakdown: {
      priceComponent,
      exclusivityBonus,
      freshnessPenalty
    }
  }
}

export const createOfferTermsHash = (
  programId: string,
  parts: string[]
): string => {
  const hash = createHash('sha256')
  hash.update(programId)
  for (const part of parts) {
    hash.update(part)
  }
  return hash.digest('hex')
}
