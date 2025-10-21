import { eq, sql } from 'drizzle-orm'
import type { CatalogSource } from '~/types'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'

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

const updateRecord = (record: CatalogRecord, vendorName: string, productName: string) => {
  if (productName && productName.length > record.productName.length) {
    record.productName = productName
  }
  if (vendorName && vendorName.length > record.vendorName.length) {
    record.vendorName = vendorName
  }
}

const collectProducts = (rows: ProductRow[], source: CatalogSource, target: Map<string, CatalogRecord>) => {
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

export const rebuildProductCatalog = (db: DrizzleDatabase) => {
  const marketRows = db
    .select({
      vendor: tables.productCatalog.vendorName,
      product: tables.productCatalog.productName,
      vendorKey: tables.productCatalog.vendorKey,
      productKey: tables.productCatalog.productKey,
      sources: tables.productCatalog.sources
    })
    .from(tables.productCatalog)
    .where(sql`${tables.productCatalog.sources} LIKE '%"market"%'`)
    .all()

  const kevRows = db
    .select({ vendor: tables.vulnerabilityEntries.vendor, product: tables.vulnerabilityEntries.product })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, 'kev'))
    .groupBy(tables.vulnerabilityEntries.vendor, tables.vulnerabilityEntries.product)
    .all()

  const enisaRows = db
    .select({ vendor: tables.vulnerabilityEntries.vendor, product: tables.vulnerabilityEntries.product })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, 'enisa'))
    .groupBy(tables.vulnerabilityEntries.vendor, tables.vulnerabilityEntries.product)
    .all()

  const historicRows = db
    .select({ vendor: tables.vulnerabilityEntries.vendor, product: tables.vulnerabilityEntries.product })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, 'historic'))
    .groupBy(tables.vulnerabilityEntries.vendor, tables.vulnerabilityEntries.product)
    .all()

  const metasploitRows = db
    .select({ vendor: tables.vulnerabilityEntries.vendor, product: tables.vulnerabilityEntries.product })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, 'metasploit'))
    .groupBy(tables.vulnerabilityEntries.vendor, tables.vulnerabilityEntries.product)
    .all()

  const catalog = new Map<string, CatalogRecord>()

  collectProducts(kevRows, 'kev', catalog)
  collectProducts(enisaRows, 'enisa', catalog)
  collectProducts(historicRows, 'historic', catalog)
  collectProducts(metasploitRows, 'metasploit', catalog)

  for (const row of marketRows) {
    const vendorName = row.vendor ?? ''
    const productName = row.product ?? ''
    const normalised = normaliseVendorProduct({ vendor: vendorName, product: productName })
    const { key: productKey, label: normalisedProduct } = normalised.product
    const { key: vendorKey, label: normalisedVendor } = normalised.vendor

    const existing = catalog.get(productKey)
    if (existing) {
      existing.sources.add('market')
      updateRecord(existing, vendorName || normalisedVendor, productName || normalisedProduct)
      continue
    }

    catalog.set(productKey, {
      productKey,
      productName: productName || normalisedProduct,
      vendorKey,
      vendorName: vendorName || normalisedVendor,
      sources: new Set<CatalogSource>(['market'])
    })
  }

  db.transaction(tx => {
    tx.delete(tables.productCatalog).run()

    for (const record of catalog.values()) {
      tx
        .insert(tables.productCatalog)
        .values({
          productKey: record.productKey,
          productName: record.productName,
          vendorKey: record.vendorKey,
          vendorName: record.vendorName,
          sources: JSON.stringify(Array.from(record.sources)),
          searchTerms: toSearchTerms(record.vendorName, record.productName)
        })
        .run()
    }
  })
}
