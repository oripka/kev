import { getDatabase } from '../../utils/sqlite'

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

export default defineEventHandler<AdminSoftwareResponse>(() => {
  const db = getDatabase()

  const productRows = db
    .prepare<ProductRow>(
      `SELECT vendor_key, vendor_name, product_key, product_name, COUNT(*) as count
       FROM user_product_filters
       GROUP BY vendor_key, vendor_name, product_key, product_name
       ORDER BY count DESC`
    )
    .all() as ProductRow[]

  const vendorRows = db
    .prepare<VendorRow>(
      `SELECT vendor_key, vendor_name, COUNT(*) as count
       FROM user_product_filters
       GROUP BY vendor_key, vendor_name
       ORDER BY count DESC`
    )
    .all() as VendorRow[]

  const sessionCount = db
    .prepare<TotalRow>('SELECT COUNT(*) as count FROM user_sessions')
    .get() as TotalRow | undefined

  const selectionCount = db
    .prepare<TotalRow>('SELECT COUNT(*) as count FROM user_product_filters')
    .get() as TotalRow | undefined

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
