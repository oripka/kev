import type { Database as SqliteDatabase } from 'better-sqlite3'
import type { CatalogSource } from '~/types'
import { normaliseVendorProduct } from '~/utils/vendorProduct'

const toSearchTerms = (vendorName: string, productName: string) =>
  `${vendorName} ${productName}`.toLowerCase()

type ProductRow = { vendor: string | null; product: string | null }

type CatalogRecord = {
  productKey: string
  productName: string
  vendorKey: string
  vendorName: string
  sources: Set<CatalogSource>
}

const updateRecord = (
  record: CatalogRecord,
  vendorName: string,
  productName: string
) => {
  if (productName && productName.length > record.productName.length) {
    record.productName = productName
  }
  if (vendorName && vendorName.length > record.vendorName.length) {
    record.vendorName = vendorName
  }
}

const collectProducts = (
  rows: ProductRow[],
  source: CatalogSource,
  target: Map<string, CatalogRecord>
) => {
  for (const row of rows) {
    const normalised = normaliseVendorProduct({ vendor: row.vendor, product: row.product })
    const { key: productKey, label: productName } = normalised.product
    const { key: vendorKey, label: vendorName } = normalised.vendor

    if (!productKey) {
      continue
    }

    const existing = target.get(productKey)
    if (existing) {
      existing.sources.add(source)
      updateRecord(existing, vendorName, productName)
      continue
    }

    target.set(productKey, {
      productKey,
      productName,
      vendorKey,
      vendorName,
      sources: new Set<CatalogSource>([source])
    })
  }
}

export const rebuildProductCatalog = (db: SqliteDatabase) => {
  const kevRows = db
    .prepare<ProductRow>(
      `SELECT DISTINCT vendor, product FROM vulnerability_entries WHERE source = 'kev'`
    )
    .all() as ProductRow[]

  const enisaRows = db
    .prepare<ProductRow>(
      `SELECT DISTINCT vendor, product FROM vulnerability_entries WHERE source = 'enisa'`
    )
    .all() as ProductRow[]

  const catalog = new Map<string, CatalogRecord>()

  collectProducts(kevRows, 'kev', catalog)
  collectProducts(enisaRows, 'enisa', catalog)

  const deleteAll = db.prepare('DELETE FROM product_catalog')
  const insert = db.prepare<{
    productKey: string
    productName: string
    vendorKey: string
    vendorName: string
    sources: string
    searchTerms: string
  }>(
    `INSERT INTO product_catalog (
      product_key,
      product_name,
      vendor_key,
      vendor_name,
      sources,
      search_terms
    ) VALUES (
      @productKey,
      @productName,
      @vendorKey,
      @vendorName,
      @sources,
      @searchTerms
    )`
  )

  const transaction = db.transaction(() => {
    deleteAll.run()

    for (const record of catalog.values()) {
      insert.run({
        productKey: record.productKey,
        productName: record.productName,
        vendorKey: record.vendorKey,
        vendorName: record.vendorName,
        sources: JSON.stringify(Array.from(record.sources)),
        searchTerms: toSearchTerms(record.vendorName, record.productName)
      })
    }
  })

  transaction()
}
