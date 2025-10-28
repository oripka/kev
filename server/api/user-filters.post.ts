import { and, eq, inArray, not, sql } from 'drizzle-orm'
import { createError, readBody } from 'h3'
import { z } from 'zod'
import { tables, useDrizzle } from '../utils/drizzle'

const productSchema = z.object({
  productKey: z.string().min(1),
  productName: z.string().min(1),
  vendorKey: z.string().min(1),
  vendorName: z.string().min(1)
})

const bodySchema = z.object({
  sessionId: z.string().min(1),
  products: z.array(productSchema)
})

export default defineEventHandler(async event => {
  const parsed = bodySchema.safeParse(await readBody(event))

  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid request payload',
      data: parsed.error.flatten()
    })
  }

  const { sessionId, products } = parsed.data
  const uniqueProducts = Array.from(new Map(products.map(item => [item.productKey, item])).values())
  const db = useDrizzle()

  await db
    .insert(tables.userSessions)
    .values({ id: sessionId })
    .onConflictDoNothing()
    .run()

  const items = uniqueProducts

  if (!items.length) {
    await db
      .delete(tables.userProductFilters)
      .where(eq(tables.userProductFilters.sessionId, sessionId))
      .run()
  } else {
    const keys = items.map(item => item.productKey)

    await db
      .delete(tables.userProductFilters)
      .where(
        and(
          eq(tables.userProductFilters.sessionId, sessionId),
          not(inArray(tables.userProductFilters.productKey, keys))
        )
      )
      .run()

    for (const item of items) {
      await db
        .insert(tables.userProductFilters)
        .values({
          sessionId,
          vendorKey: item.vendorKey,
          vendorName: item.vendorName,
          productKey: item.productKey,
          productName: item.productName
        })
        .onConflictDoUpdate({
          target: [tables.userProductFilters.sessionId, tables.userProductFilters.productKey],
          set: {
            vendorKey: item.vendorKey,
            vendorName: item.vendorName,
            productName: item.productName,
            updatedAt: sql`CURRENT_TIMESTAMP`
          }
        })
        .run()
    }
  }

  const result = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(tables.userProductFilters)
    .where(eq(tables.userProductFilters.sessionId, sessionId))
    .get()

  return {
    saved: result?.count ?? 0
  }
})
