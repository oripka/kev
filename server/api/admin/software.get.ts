import { sql, tables, useDrizzle } from '../../utils/drizzle'
import { requireAdminKey } from '../../utils/adminAuth'

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

export default defineEventHandler<AdminSoftwareResponse>(async event => {
  requireAdminKey(event)

  const db = useDrizzle()

  const productQuery = db
    .select({
      vendor_key: tables.userProductFilters.vendorKey,
      vendor_name: tables.userProductFilters.vendorName,
      product_key: tables.userProductFilters.productKey,
      product_name: tables.userProductFilters.productName,
      count: sql<number>`count(*)`
    })
    .from(tables.userProductFilters)
    .groupBy(
      tables.userProductFilters.vendorKey,
      tables.userProductFilters.vendorName,
      tables.userProductFilters.productKey,
      tables.userProductFilters.productName
    )
    .orderBy(sql`count(*) DESC`)

  const vendorQuery = db
    .select({
      vendor_key: tables.userProductFilters.vendorKey,
      vendor_name: tables.userProductFilters.vendorName,
      count: sql<number>`count(*)`
    })
    .from(tables.userProductFilters)
    .groupBy(
      tables.userProductFilters.vendorKey,
      tables.userProductFilters.vendorName
    )
    .orderBy(sql`count(*) DESC`)

  const sessionCountQuery = db
    .select({ count: sql<number>`count(*)` })
    .from(tables.userSessions)
    .limit(1)

  const selectionCountQuery = db
    .select({ count: sql<number>`count(*)` })
    .from(tables.userProductFilters)
    .limit(1)

  const [productRows, vendorRows, sessionCountRow, selectionCountRow] = await Promise.all([
    productQuery.all(),
    vendorQuery.all(),
    sessionCountQuery.get(),
    selectionCountQuery.get()
  ])

  return {
    totals: {
      sessions: sessionCountRow ? Number(sessionCountRow.count) : 0,
      trackedSelections: selectionCountRow ? Number(selectionCountRow.count) : 0,
      uniqueProducts: productRows.length,
      uniqueVendors: vendorRows.length
    },
    products: productRows.map(row => ({
      vendorKey: row.vendor_key,
      vendorName: row.vendor_name,
      productKey: row.product_key,
      productName: row.product_name,
      selections: Number(row.count)
    })),
    vendors: vendorRows.map(row => ({
      vendorKey: row.vendor_key,
      vendorName: row.vendor_name,
      selections: Number(row.count)
    }))
  }
})
