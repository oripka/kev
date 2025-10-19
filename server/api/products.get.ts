import { getQuery } from 'h3'
import { sql } from 'drizzle-orm'
import { tables } from '../database/client'
import { getDatabase } from '../utils/sqlite'
import type { CatalogSource, ProductCatalogItem, ProductCatalogResponse } from '~/types'
import { normaliseVendorProduct } from '~/utils/vendorProduct'

interface ProductCatalogRow {
  product_key: string
  product_name: string
  vendor_key: string
  vendor_name: string
  sources: string
}

interface KevCountRow {
  vendor: string | null
  product: string | null
  count: number
}

const toSources = (value: string): CatalogSource[] => {
  try {
    const parsed = JSON.parse(value) as unknown
    if (Array.isArray(parsed)) {
      const items = parsed.filter((entry): entry is CatalogSource => entry === 'kev' || entry === 'enisa')
      return items.length ? items : ['kev']
    }
  } catch {
    // Fall back to the default source list when parsing fails.
  }
  return ['kev']
}

const escapeLike = (value: string) => value.replace(/([%_\\])/g, '\\$1')

const normaliseLimit = (value: unknown): number => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.min(500, Math.max(1, Math.trunc(value)))
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number.parseInt(value.trim(), 10)
    if (!Number.isNaN(parsed)) {
      return Math.min(500, Math.max(1, parsed))
    }
  }

  return 100
}

export default defineEventHandler((event): ProductCatalogResponse => {
  const query = getQuery(event)
  const rawSearch = typeof query.q === 'string' ? query.q.trim().toLowerCase() : ''
  const search = rawSearch.length >= 2 ? rawSearch : ''
  const limit = normaliseLimit(query.limit)

  const db = getDatabase()
  const kevCountRows = db.all(
    sql<KevCountRow>`
      SELECT vendor, product, COUNT(*) as count
      FROM ${tables.vulnerabilityEntries}
      WHERE source = 'kev'
      GROUP BY vendor, product
    `
  )

  const kevCountByProduct = new Map<string, number>()

  for (const row of kevCountRows) {
    const normalised = normaliseVendorProduct({ vendor: row.vendor, product: row.product })
    kevCountByProduct.set(normalised.product.key, row.count ?? 0)
  }

  let rows: ProductCatalogRow[]

  if (search) {
    const pattern = `%${escapeLike(search)}%`
    rows = db.all(
      sql<ProductCatalogRow>`
        SELECT product_key, product_name, vendor_key, vendor_name, sources
        FROM ${tables.productCatalog}
        WHERE search_terms LIKE ${pattern} ESCAPE '\\'
        ORDER BY product_name ASC
        LIMIT ${limit}
      `
    )
  } else {
    const fetched = db
      .select({
        product_key: tables.productCatalog.productKey,
        product_name: tables.productCatalog.productName,
        vendor_key: tables.productCatalog.vendorKey,
        vendor_name: tables.productCatalog.vendorName,
        sources: tables.productCatalog.sources
      })
      .from(tables.productCatalog)
      .orderBy(tables.productCatalog.productName)
      .all()

    rows = fetched
      .sort((a, b) => {
        const countA = kevCountByProduct.get(a.product_key) ?? 0
        const countB = kevCountByProduct.get(b.product_key) ?? 0

        if (countA !== countB) {
          return countB - countA
        }

        return a.product_name.localeCompare(b.product_name)
      })
      .slice(0, limit)
  }

  const items: ProductCatalogItem[] = rows.map(row => ({
    productKey: row.product_key,
    productName: row.product_name,
    vendorKey: row.vendor_key,
    vendorName: row.vendor_name,
    sources: toSources(row.sources),
    kevCount: kevCountByProduct.get(row.product_key) ?? 0
  }))

  return { items }
})
