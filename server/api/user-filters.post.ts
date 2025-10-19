import { z } from 'zod'
import { getDatabase } from '../utils/sqlite'

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
  const uniqueProducts = Array.from(
    new Map(products.map(item => [item.productKey, item])).values()
  )
  const db = getDatabase()

  const ensureSession = db.prepare('INSERT INTO user_sessions (id) VALUES (?) ON CONFLICT(id) DO NOTHING')
  ensureSession.run(sessionId)

  const upsert = db.prepare(`
    INSERT INTO user_product_filters (
      session_id,
      vendor_key,
      vendor_name,
      product_key,
      product_name,
      created_at,
      updated_at
    ) VALUES (
      @sessionId,
      @vendorKey,
      @vendorName,
      @productKey,
      @productName,
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP
    )
    ON CONFLICT(session_id, product_key) DO UPDATE SET
      vendor_key = excluded.vendor_key,
      vendor_name = excluded.vendor_name,
      product_name = excluded.product_name,
      updated_at = CURRENT_TIMESTAMP
  `)

  const deleteAll = db.prepare('DELETE FROM user_product_filters WHERE session_id = ?')

  const transaction = db.transaction((items: typeof uniqueProducts) => {
    if (!items.length) {
      deleteAll.run(sessionId)
      return
    }

    const placeholders = items.map(() => '?').join(', ')
    const deleteMissing = db.prepare(
      `DELETE FROM user_product_filters
       WHERE session_id = ?
         AND product_key NOT IN (${placeholders})`
    )
    deleteMissing.run(sessionId, ...items.map(item => item.productKey))

    for (const item of items) {
      upsert.run({
        sessionId,
        vendorKey: item.vendorKey,
        vendorName: item.vendorName,
        productKey: item.productKey,
        productName: item.productName
      })
    }
  })

  transaction(uniqueProducts)

  const countStatement = db.prepare(
    'SELECT COUNT(*) as count FROM user_product_filters WHERE session_id = ?'
  )
  const { count } = countStatement.get(sessionId) as { count: number }

  return {
    saved: count
  }
})
