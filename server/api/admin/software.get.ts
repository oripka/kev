import { sql } from 'drizzle-orm'
import { tables } from '../../database/client'
import { getDatabase } from '../../utils/sqlite'
import { requireAdminKey } from '../../utils/adminAuth'

type ProductRow = {
  vendor_key: string
  vendor_name: string
  product_key: string
  product_name: string
  count: number
}

type VendorRow = {
  vendor_key: string
  vendor_name: string
  count: number
}

type TotalRow = {
  count: number
}

type AdminSoftwareResponse = {
  totals: {
    sessions: number
    trackedSelections: number
    uniqueProducts: number
    uniqueVendors: number
  }
  products: Array<{
    vendorKey: string
    vendorName: string
    productKey: string
    productName: string
    selections: number
  }>
  vendors: Array<{
    vendorKey: string
    vendorName: string
    selections: number
  }>
}

export default defineEventHandler<AdminSoftwareResponse>(event => {
  requireAdminKey(event)

  const db = getDatabase()

  const productRows = db.all(
    sql<ProductRow>`
      SELECT vendor_key, vendor_name, product_key, product_name, COUNT(*) as count
      FROM ${tables.userProductFilters}
      GROUP BY vendor_key, vendor_name, product_key, product_name
      ORDER BY count DESC
    `
  )

  const vendorRows = db.all(
    sql<VendorRow>`
      SELECT vendor_key, vendor_name, COUNT(*) as count
      FROM ${tables.userProductFilters}
      GROUP BY vendor_key, vendor_name
      ORDER BY count DESC
    `
  )

  const sessionCount = db.get(
    sql<TotalRow>`SELECT COUNT(*) as count FROM ${tables.userSessions}`
  )

  const selectionCount = db.get(
    sql<TotalRow>`SELECT COUNT(*) as count FROM ${tables.userProductFilters}`
  )

  return {
    totals: {
      sessions: sessionCount?.count ?? 0,
      trackedSelections: selectionCount?.count ?? 0,
      uniqueProducts: productRows.length,
      uniqueVendors: vendorRows.length
    },
    products: productRows.map(row => ({
      vendorKey: row.vendor_key,
      vendorName: row.vendor_name,
      productKey: row.product_key,
      productName: row.product_name,
      selections: row.count
    })),
    vendors: vendorRows.map(row => ({
      vendorKey: row.vendor_key,
      vendorName: row.vendor_name,
      selections: row.count
    }))
  }
})
