import { eq } from 'drizzle-orm'
import { tables } from './drizzle'
import { useDrizzle, resetDatabase as resetClientDatabase, type DrizzleDatabase } from '../database/client'

/**
 * Legacy compatibility helpers retained for modules that still import `server/utils/sqlite`.
 * New code should depend on `server/utils/drizzle` and the async metadata helpers instead.
 */
export { type DrizzleDatabase }

export const getDatabase = (): DrizzleDatabase => useDrizzle()

export const ensureCatalogTables = async () => {
  // Tables are managed via Drizzle migrations; nothing to do here.
}

export const getMetadata = async (key: string): Promise<string | null> => {
  const db = useDrizzle()
  const row = await db
    .select({ value: tables.kevMetadata.value })
    .from(tables.kevMetadata)
    .where(eq(tables.kevMetadata.key, key))
    .get()

  return row?.value ?? null
}

export const setMetadata = async (key: string, value: string): Promise<void> => {
  const db = useDrizzle()
  await db
    .insert(tables.kevMetadata)
    .values({ key, value })
    .onConflictDoUpdate({ target: tables.kevMetadata.key, set: { value } })
    .run()
}

export const resetDatabase = (): void => {
  resetClientDatabase()
}
