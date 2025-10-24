// import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
// import { useDrizzle as useDatabaseClient, tables } from '~/server/database/client'
// import { useStorage } from '#imports'
// import type * as schema from '~/server/database/schema'

// const storage = useStorage()

// export { tables }

// export function useDrizzle(): BetterSQLite3Database<typeof schema> {
//   // Ensure the data storage is initialised for environments such as Nitro edge.
//   void storage.getMount?.('data')
//   return useDatabaseClient()
// }

import { drizzle } from 'drizzle-orm/d1'
export { sql, eq, and, or } from 'drizzle-orm'

import * as schema from '../server/database/schema'

export const tables = schema

export function useDrizzle() {
  return drizzle(hubDatabase(), { schema })
}

export type User = typeof schema.users.$inferSelect
