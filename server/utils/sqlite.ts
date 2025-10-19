import { eq } from 'drizzle-orm'
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
import { useDrizzle, resetDatabase as reset, tables, useSqlite } from '../database/client'

export type DrizzleDatabase = BetterSQLite3Database<typeof tables>

export const getDatabase = (): DrizzleDatabase => useDrizzle()

export const getSqlite = useSqlite

export const ensureCatalogTables = (_db?: DrizzleDatabase) => {
  // Tables are created automatically on initialisation via server/database/client.
}

export const getMetadata = (key: string): string | null => {
  const db = getDatabase()
  const row = db.select().from(tables.kevMetadata).where(eq(tables.kevMetadata.key, key)).get()
  return row?.value ?? null
}

export const setMetadata = (key: string, value: string) => {
  const db = getDatabase()
  db
    .insert(tables.kevMetadata)
    .values({ key, value })
    .onConflictDoUpdate({ target: tables.kevMetadata.key, set: { value } })
    .run()
}

export const resetDatabase = () => {
  reset()
}
