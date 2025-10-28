import { eq, inArray, tables, useDrizzle } from './drizzle'

export async function getMetadataValue(key: string): Promise<string | null> {
  const db = useDrizzle()
  const row = await db
    .select({ value: tables.kevMetadata.value })
    .from(tables.kevMetadata)
    .where(eq(tables.kevMetadata.key, key))
    .get()

  return row?.value ?? null
}

export async function getMetadataMap(keys: string[]): Promise<Record<string, string | null>> {
  if (!keys.length) {
    return {}
  }

  const uniqueKeys = Array.from(new Set(keys))
  const db = useDrizzle()
  const rows = await db
    .select({ key: tables.kevMetadata.key, value: tables.kevMetadata.value })
    .from(tables.kevMetadata)
    .where(inArray(tables.kevMetadata.key, uniqueKeys))
    .all()

  const defaultEntries = Object.fromEntries(uniqueKeys.map(key => [key, null])) as Record<string, string | null>

  for (const row of rows) {
    if (row.key) {
      defaultEntries[row.key] = row.value ?? null
    }
  }

  return defaultEntries
}

export async function setMetadataValue(key: string, value: string): Promise<void> {
  const db = useDrizzle()
  await db
    .insert(tables.kevMetadata)
    .values({ key, value })
    .onConflictDoUpdate({ target: tables.kevMetadata.key, set: { value } })
    .run()
}
