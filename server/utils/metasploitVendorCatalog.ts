import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { normaliseVendorProduct } from '~/utils/vendorProduct'

export type CatalogVendorProduct = {
  vendor: string
  product: string
  cves?: string[]
  sources?: string[]
}

type CatalogHint = {
  vendor: string
  product: string
  keywords: string[]
}

const DATASET_PATH = join(process.cwd(), 'datasets', 'metasploit_vendor_products.json')

const GENERIC_PRODUCT_NAMES = new Set([
  'windows',
  'linux',
  'unix',
  'macos',
  'android',
  'ios'
])

const GENERIC_PRODUCT_PATTERNS = [
  /\bmultiple\b/i,
  /\bvarious\b/i,
  /\bunspecified\b/i,
  /\bunknown\b/i,
  /\bgeneric\b/i,
  /\bproducts?\b/i,
  /\bdevices?\b/i,
  /\bsystems?\b/i,
  /\bsolutions?\b/i
]

const GENERIC_KEYWORDS = new Set([
  'application',
  'applications',
  'component',
  'components',
  'framework',
  'manager',
  'management',
  'module',
  'modules',
  'platform',
  'product',
  'products',
  'server',
  'servers',
  'service',
  'services',
  'software',
  'solution',
  'solutions',
  'system',
  'systems',
  'task scheduler'
])

const cleanKeyword = (value: string): string =>
  value
    .toLowerCase()
    .replace(/["'`’‘“”]+/g, '')
    .replace(/[^a-z0-9+]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()

const hasMeaningfulLength = (keyword: string): boolean => keyword.length >= 4 || /\d/.test(keyword)

const isAlphaNumeric = (value: string): boolean => /[a-z0-9]/i.test(value)

const containsKeywordWithBoundaries = (text: string, keyword: string): boolean => {
  if (!keyword) {
    return false
  }

  let startIndex = 0
  while (startIndex <= text.length) {
    const matchIndex = text.indexOf(keyword, startIndex)
    if (matchIndex === -1) {
      break
    }

    const beforeChar = matchIndex > 0 ? text.charAt(matchIndex - 1) : ''
    const afterPosition = matchIndex + keyword.length
    const afterChar = afterPosition < text.length ? text.charAt(afterPosition) : ''
    const hasValidPrefix = !beforeChar || !isAlphaNumeric(beforeChar)
    const hasValidSuffix = !afterChar || !isAlphaNumeric(afterChar)

    if (hasValidPrefix && hasValidSuffix) {
      return true
    }

    startIndex = matchIndex + 1
  }

  return false
}

const extractKeywordVariants = (vendor: string, product: string): string[] => {
  const variants = new Set<string>()

  const push = (text: string | null | undefined) => {
    if (!text) {
      return
    }
    const cleaned = cleanKeyword(text)
    if (!cleaned || !hasMeaningfulLength(cleaned)) {
      return
    }
    if (GENERIC_KEYWORDS.has(cleaned)) {
      return
    }
    variants.add(cleaned)
  }

  const vendorClean = cleanKeyword(vendor)

  const rawProductVariants: string[] = []
  rawProductVariants.push(product)
  const withoutParens = product.replace(/\([^)]*\)/g, ' ')
  rawProductVariants.push(withoutParens)

  const beforeParen = product.split('(')[0]
  if (beforeParen && beforeParen.trim().length) {
    rawProductVariants.push(beforeParen)
  }

  const parenMatches = Array.from(product.matchAll(/\(([^)]+)\)/g), match => match[1])
  rawProductVariants.push(...parenMatches)

  const slashSegments = product.split(/[\/]/g)
  if (slashSegments.length > 1) {
    rawProductVariants.push(...slashSegments)
    rawProductVariants.push(...slashSegments.map(segment => segment.replace(/\([^)]*\)/g, ' ')))
  }

  const slashlessSegments = withoutParens.split(/[\/]/g)
  if (slashlessSegments.length > 1) {
    rawProductVariants.push(...slashlessSegments)
  }

  const hyphenSegments = product.split(/\s*[–-]\s*/g)
  if (hyphenSegments.length > 1) {
    rawProductVariants.push(...hyphenSegments)
  }

  for (const variant of rawProductVariants) {
    push(variant)
    if (vendorClean) {
      push(`${vendor} ${variant}`)
    }
  }

  return Array.from(variants)
}

const shouldSkipEntry = (entry: CatalogVendorProduct): boolean => {
  const vendor = entry.vendor?.trim()
  const product = entry.product?.trim()
  if (!vendor || !product) {
    return true
  }

  const productLower = product.toLowerCase()
  if (GENERIC_PRODUCT_NAMES.has(productLower)) {
    return true
  }

  if (GENERIC_PRODUCT_PATTERNS.some(pattern => pattern.test(product))) {
    return true
  }

  return false
}

let cachedHints: CatalogHint[] | null = null

const buildCatalogHints = (entries: CatalogVendorProduct[]): CatalogHint[] => {
  const hints: CatalogHint[] = []
  const seen = new Set<string>()

  for (const entry of entries) {
    if (shouldSkipEntry(entry)) {
      continue
    }

    const normalised = normaliseVendorProduct({ vendor: entry.vendor, product: entry.product })
    const vendorLabel = normalised.vendor.label
    const productLabel = normalised.product.label
    const key = `${normalised.vendor.key}__${normalised.product.key}`
    if (seen.has(key)) {
      continue
    }

    const keywords = extractKeywordVariants(vendorLabel, productLabel)
    if (!keywords.length) {
      continue
    }

    seen.add(key)
    hints.push({ vendor: vendorLabel, product: productLabel, keywords })
  }

  return hints
}

const loadCatalogHints = (): CatalogHint[] => {
  if (cachedHints) {
    return cachedHints
  }

  try {
    const raw = readFileSync(DATASET_PATH, 'utf8')
    const parsed = JSON.parse(raw) as CatalogVendorProduct[]
    cachedHints = buildCatalogHints(parsed)
  } catch {
    cachedHints = []
  }

  return cachedHints
}

export const matchVendorProductByTitle = (
  text: string | Array<string | null | undefined>
): { vendor: string; product: string } | null => {
  const segments = Array.isArray(text) ? text : [text]
  const joined = segments
    .map(segment => (typeof segment === 'string' ? segment : ''))
    .filter(Boolean)
    .join(' ')

  if (!joined) {
    return null
  }

  const lower = joined.toLowerCase()

  for (const hint of loadCatalogHints()) {
    if (hint.keywords.some(keyword => containsKeywordWithBoundaries(lower, keyword))) {
      if (
        hint.vendor === 'Microsoft' &&
        hint.product === 'Windows' &&
        !/\bmicrosoft\b/.test(lower)
      ) {
        continue
      }
      return { vendor: hint.vendor, product: hint.product }
    }
  }

  return null
}
