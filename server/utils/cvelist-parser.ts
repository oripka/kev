import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { normaliseVendorProduct } from '~/utils/vendorProduct'

export const CVELIST_REPO_DIR = join(process.cwd(), 'data', 'cache', 'cvelist', 'cvelistV5')

const NORMALISED_WHITESPACE = /\s+/g

const normaliseLabel = (value: unknown): string => {
  if (typeof value !== 'string') {
    return ''
  }
  return value.trim().replace(NORMALISED_WHITESPACE, ' ')
}

const splitProductNames = (value: string): string[] => {
  if (!value.includes(',')) {
    return [value.trim()]
  }

  const tokens = value
    .split(',')
    .map(token => token.trim())
    .filter(token => token.length > 0)

  if (tokens.length <= 1) {
    return [value.trim()]
  }

  const hasListFormatting = /,\s/.test(value)
  if (!hasListFormatting) {
    return [value.trim()]
  }

  return tokens
}

const mergeUnique = <T>(target: T[], values: T[], key: (item: T) => string) => {
  const seen = new Set(target.map(item => key(item)))
  for (const value of values) {
    const identifier = key(value)
    if (seen.has(identifier)) {
      continue
    }
    seen.add(identifier)
    target.push(value)
  }
}

const mergeUniqueStrings = (target: string[], values: Iterable<string>) => {
  const seen = new Set(target.map(value => value.toLowerCase()))
  for (const value of values) {
    const trimmed = value.trim()
    if (!trimmed) {
      continue
    }
    const key = trimmed.toLowerCase()
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    target.push(trimmed)
  }
}

const parseCpeUri = (
  value: string
): { vendor: string; product: string; version?: string | null } | null => {
  const segments = value.split(':')
  if (segments.length < 6) {
    return null
  }
  const vendor = normaliseLabel(segments[3])
  const product = normaliseLabel(segments[4])
  const version = normaliseLabel(segments[5])
  if (!vendor || !product) {
    return null
  }
  return { vendor, product, version: version || null }
}

const toStatus = (status?: string | null, fallback?: string | null) => {
  const candidate = status ?? fallback ?? null
  if (!candidate) {
    return null
  }
  return candidate.trim() || null
}

export interface NormalisedVersion {
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

export interface NormalisedProduct {
  product: string
  productKey: string
  versions: NormalisedVersion[]
  platforms: string[]
  status?: string | null
  source: 'cna' | 'adp' | 'cpe'
}

export interface NormalisedVendorImpact {
  vendor: string
  vendorKey: string
  products: NormalisedProduct[]
}

export interface NormalisedProblemType {
  cweId?: string
  description: string
  source: 'cna' | 'adp'
}

export interface NormalisedDescription {
  lang: string
  value: string
  source: 'cna' | 'adp'
}

export interface CvelistRecordSummary {
  cveId: string
  vendors: NormalisedVendorImpact[]
  cwes: NormalisedProblemType[]
  references: string[]
  descriptions: NormalisedDescription[]
  datePublished?: string
  dateUpdated?: string
  assigner?: string
}

type VendorCollectionEntry = NormalisedVendorImpact & { productMap: Map<string, NormalisedProduct> }

const resolveProductImpact = (
  collection: Map<string, VendorCollectionEntry>,
  vendorName: string,
  productName: string,
  source: NormalisedProduct['source']
): NormalisedProduct => {
  const normalised = normaliseVendorProduct({ vendor: vendorName, product: productName })
  const vendorKey = normalised.vendor.key
  let vendorImpact = collection.get(vendorKey)

  if (!vendorImpact) {
    vendorImpact = {
      vendor: normalised.vendor.label,
      vendorKey,
      products: [],
      productMap: new Map<string, NormalisedProduct>()
    }
    collection.set(vendorKey, vendorImpact)
  } else if (!vendorImpact.vendor && normalised.vendor.label) {
    vendorImpact.vendor = normalised.vendor.label
  }

  const productKey = normalised.product.key
  let productImpact = vendorImpact.productMap.get(productKey)

  if (!productImpact) {
    productImpact = {
      product: normalised.product.label,
      productKey,
      versions: [],
      platforms: [],
      status: null,
      source
    }
    vendorImpact.productMap.set(productKey, productImpact)
    vendorImpact.products.push(productImpact)
  } else {
    if (!productImpact.product && normalised.product.label) {
      productImpact.product = normalised.product.label
    }
    if (productImpact.source !== 'cna') {
      productImpact.source = source
    }
  }

  return productImpact
}

const normaliseVersionEntry = (
  raw: Record<string, unknown>,
  defaultStatus: string | null,
  source: NormalisedProduct['source']
): NormalisedVersion => {
  const version = normaliseLabel(raw.version)
  const lessThan = normaliseLabel(raw.lessThan)
  const lessThanOrEqual = normaliseLabel(raw.lessThanOrEqual)
  const greaterThan = normaliseLabel(raw.greaterThan)
  const greaterThanOrEqual = normaliseLabel(raw.greaterThanOrEqual)
  const introduced = normaliseLabel(raw.introduced ?? raw.versionStartIncluding ?? raw.versionStart)
  const fixed = normaliseLabel(raw.fixed ?? raw.versionEndIncluding ?? raw.versionEnd)
  const status = toStatus((raw.status as string | undefined) ?? null, defaultStatus)
  const versionType = normaliseLabel(raw.versionType)

  return {
    version: version || null,
    lessThan: lessThan || null,
    lessThanOrEqual: lessThanOrEqual || null,
    greaterThan: greaterThan || null,
    greaterThanOrEqual: greaterThanOrEqual || null,
    introduced: introduced || null,
    fixed: fixed || null,
    status,
    versionType: versionType || null
  }
}

const collectAffectedFromContainer = (
  vendors: Map<string, VendorCollectionEntry>,
  container: unknown,
  source: NormalisedProduct['source']
) => {
  if (!Array.isArray(container)) {
    return
  }

  for (const item of container) {
    if (!item || typeof item !== 'object') {
      continue
    }

    const vendorName = normaliseLabel((item as Record<string, unknown>).vendor ?? '')
    const productRaw = normaliseLabel((item as Record<string, unknown>).product ?? '')
    const defaultStatus = toStatus((item as Record<string, unknown>).defaultStatus as string | undefined)

    const productNames = productRaw ? splitProductNames(productRaw) : ['Unknown']
    const platforms: string[] = []

    const rawPlatforms = (item as Record<string, unknown>).platforms
    if (Array.isArray(rawPlatforms)) {
      mergeUniqueStrings(platforms, rawPlatforms.map(value => normaliseLabel(value)))
    } else if (typeof rawPlatforms === 'string') {
      mergeUniqueStrings(platforms, [normaliseLabel(rawPlatforms)])
    }

    for (const productName of productNames) {
      const productImpact = resolveProductImpact(
        vendors,
        vendorName || 'Unknown Vendor',
        productName || 'Unknown Product',
        source
      )
      const versionsRaw = (item as Record<string, unknown>).versions
      if (Array.isArray(versionsRaw)) {
        const normalisedVersions = versionsRaw
          .map(entry =>
            entry && typeof entry === 'object'
              ? normaliseVersionEntry(entry as Record<string, unknown>, defaultStatus, source)
              : null
          )
          .filter((entry): entry is NormalisedVersion => entry !== null)

        mergeUnique(productImpact.versions, normalisedVersions, version => JSON.stringify(version))
      }

      if (platforms.length) {
        mergeUniqueStrings(productImpact.platforms, platforms)
      }

      productImpact.status = toStatus((item as Record<string, unknown>).status as string | undefined, defaultStatus)
    }
  }
}

const collectAffectedFromCpe = (
  vendors: Map<string, VendorCollectionEntry>,
  cpeNodes: unknown
) => {
  if (!Array.isArray(cpeNodes)) {
    return
  }

  for (const node of cpeNodes) {
    if (!node || typeof node !== 'object') {
      continue
    }

    const matches = (node as Record<string, unknown>).cpeMatch
    if (!Array.isArray(matches)) {
      continue
    }

    for (const match of matches) {
      if (!match || typeof match !== 'object') {
        continue
      }

      const criteria = normaliseLabel((match as Record<string, unknown>).criteria ?? '')
      const cpe23Uri = normaliseLabel((match as Record<string, unknown>).cpe23Uri ?? criteria)
      if (!cpe23Uri) {
        continue
      }

      const parsed = parseCpeUri(cpe23Uri)
      if (!parsed) {
        continue
      }

      const productImpact = resolveProductImpact(
        vendors,
        parsed.vendor || 'Unknown Vendor',
        parsed.product || 'Unknown Product',
        'cpe'
      )

      const versionRange: NormalisedVersion = {
        version: parsed.version || null,
        introduced: normaliseLabel((match as Record<string, unknown>).versionStartIncluding),
        fixed: normaliseLabel((match as Record<string, unknown>).versionEndIncluding),
        lessThan: normaliseLabel((match as Record<string, unknown>).versionEndExcluding),
        greaterThan: normaliseLabel((match as Record<string, unknown>).versionStartExcluding),
        status: (match as Record<string, unknown>).vulnerable === false ? 'unaffected' : 'affected'
      }

      mergeUnique(productImpact.versions, [versionRange], version => JSON.stringify(version))
    }
  }
}

const collectProblemTypes = (
  containers: unknown,
  source: 'cna' | 'adp',
  target: NormalisedProblemType[]
) => {
  if (!Array.isArray(containers)) {
    return
  }

  for (const entry of containers) {
    if (!entry || typeof entry !== 'object') {
      continue
    }

    const descriptions = (entry as Record<string, unknown>).descriptions
    if (!Array.isArray(descriptions)) {
      continue
    }

    for (const description of descriptions) {
      if (!description || typeof description !== 'object') {
        continue
      }

      const value = normaliseLabel((description as Record<string, unknown>).description ?? '')
      if (!value) {
        continue
      }

      const cweId = normaliseLabel((description as Record<string, unknown>).cweId ?? '') || undefined
      target.push({ cweId, description: value, source })
    }
  }
}

const collectDescriptions = (
  container: unknown,
  source: 'cna' | 'adp',
  target: NormalisedDescription[]
) => {
  if (!Array.isArray(container)) {
    return
  }

  for (const entry of container) {
    if (!entry || typeof entry !== 'object') {
      continue
    }

    const lang = normaliseLabel((entry as Record<string, unknown>).lang ?? 'en') || 'en'
    const value = normaliseLabel((entry as Record<string, unknown>).value ?? '')
    if (!value) {
      continue
    }

    target.push({ lang, value, source })
  }
}

const collectReferences = (container: unknown, target: string[]) => {
  if (!Array.isArray(container)) {
    return
  }

  for (const entry of container) {
    if (!entry || typeof entry !== 'object') {
      continue
    }

    const url = normaliseLabel((entry as Record<string, unknown>).url ?? '')
    if (url) {
      target.push(url)
      continue
    }

    const name = normaliseLabel((entry as Record<string, unknown>).name ?? '')
    if (name) {
      target.push(name)
    }
  }
}

const buildVendorImpacts = (
  vendors: Map<string, VendorCollectionEntry>
): NormalisedVendorImpact[] => {
  return Array.from(vendors.values()).map(entry => {
    entry.products.sort((a, b) => a.product.localeCompare(b.product))
    return {
      vendor: entry.vendor,
      vendorKey: entry.vendorKey,
      products: entry.products.map(product => ({
        product: product.product,
        productKey: product.productKey,
        versions: product.versions,
        platforms: product.platforms,
        status: product.status ?? null,
        source: product.source
      }))
    }
  })
}

export const resolveCvePath = (cveId: string): string => {
  const match = /^CVE-(\d{4})-(\d{4,7})$/i.exec(cveId.trim())
  if (!match) {
    throw new Error(`Invalid CVE identifier: ${cveId}`)
  }
  const year = match[1]
  const sequenceRaw = match[2]
  const filenameSequence = sequenceRaw.padStart(4, '0')
  const bucketPrefix = filenameSequence.replace(/^0+/, '') || '0'
  const bucket = `${bucketPrefix.charAt(0)}xxx`
  return join('cves', year, bucket, `CVE-${year}-${filenameSequence}.json`)
}

export const readCveRecord = async (cveId: string): Promise<Record<string, unknown>> => {
  const path = join(CVELIST_REPO_DIR, resolveCvePath(cveId))
  const contents = await readFile(path, 'utf8').catch(error => {
    throw new Error(`Unable to read CVE ${cveId}: ${(error as Error).message}`)
  })
  try {
    const parsed = JSON.parse(contents) as Record<string, unknown>
    return parsed
  } catch (error) {
    throw new Error(`Invalid JSON for CVE ${cveId}: ${(error as Error).message}`)
  }
}

export const summariseCveRecord = (
  cveId: string,
  record: Record<string, unknown>
): CvelistRecordSummary => {
  const vendors = new Map<string, VendorCollectionEntry>()
  const cwes: NormalisedProblemType[] = []
  const references: string[] = []
  const descriptions: NormalisedDescription[] = []

  const containers = record.containers as Record<string, unknown> | undefined

  if (containers?.cna) {
    const cna = containers.cna as Record<string, unknown>
    collectAffectedFromContainer(vendors, cna.affected, 'cna')
    collectProblemTypes(cna.problemTypes, 'cna', cwes)
    collectReferences(cna.references, references)
    collectDescriptions(cna.descriptions, 'cna', descriptions)

    if (!Array.isArray(cna.affected) || cna.affected.length === 0) {
      if (Array.isArray(cna.cpeApplicability)) {
        for (const applicability of cna.cpeApplicability as Array<Record<string, unknown>>) {
          if (!applicability || typeof applicability !== 'object') {
            continue
          }
          collectAffectedFromContainer(vendors, applicability.affected, 'cna')
          collectAffectedFromCpe(vendors, applicability.nodes)
        }
      }
    }
  }

  if (Array.isArray(containers?.adp)) {
    for (const adp of containers.adp as Array<Record<string, unknown>>) {
      collectAffectedFromContainer(vendors, adp.affected, 'adp')
      collectProblemTypes(adp.problemTypes, 'adp', cwes)
      collectDescriptions(adp.descriptions, 'adp', descriptions)
      collectReferences(adp.references, references)
      if (!Array.isArray(adp.affected) || adp.affected.length === 0) {
        collectAffectedFromCpe(vendors, adp.cpeApplicability?.nodes)
      }
    }
  }

  const vendorImpacts = buildVendorImpacts(vendors)

  const metadata = (record.cveMetadata ?? {}) as Record<string, unknown>

  const referenceSet = new Set<string>()
  const dedupedReferences: string[] = []
  for (const reference of references) {
    const key = reference.toLowerCase()
    if (referenceSet.has(key)) {
      continue
    }
    referenceSet.add(key)
    dedupedReferences.push(reference)
  }

  const cweMap = new Map<string, NormalisedProblemType>()
  for (const entry of cwes) {
    const key = `${entry.source}:${entry.cweId ?? ''}:${entry.description}`.toLowerCase()
    if (cweMap.has(key)) {
      continue
    }
    cweMap.set(key, entry)
  }

  const descriptionMap = new Map<string, NormalisedDescription>()
  for (const entry of descriptions) {
    const key = `${entry.source}:${entry.lang}:${entry.value}`.toLowerCase()
    if (descriptionMap.has(key)) {
      continue
    }
    descriptionMap.set(key, entry)
  }

  return {
    cveId,
    vendors: vendorImpacts,
    cwes: Array.from(cweMap.values()),
    references: dedupedReferences,
    descriptions: Array.from(descriptionMap.values()),
    datePublished: typeof metadata.datePublished === 'string' ? metadata.datePublished : undefined,
    dateUpdated: typeof metadata.dateUpdated === 'string' ? metadata.dateUpdated : undefined,
    assigner: typeof metadata.assignerShortName === 'string' ? metadata.assignerShortName : undefined
  }
}
