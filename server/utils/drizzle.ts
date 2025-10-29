import { drizzle as drizzleD1 } from 'drizzle-orm/d1'
export { sql, eq, and, or, inArray } from 'drizzle-orm'

import * as schema from '../database/schema'
import {
  useDrizzle as useFallbackDrizzle,
  tables as fallbackTables,
  type DrizzleDatabase as FallbackDrizzleDatabase
} from '../database/client'

type D1Client = Parameters<typeof drizzleD1>[0]

type HubGlobal = typeof globalThis & {
  hubDatabase?: () => D1Client
  __env__?: Record<string, unknown>
  DB?: D1Client
}

const resolveDatabaseBinding = (): D1Client | null => {
  const hub = globalThis as HubGlobal

  const processBinding =
    typeof process !== 'undefined' ? ((process.env.DB as D1Client | undefined) ?? null) : null

  if (processBinding) {
    return processBinding
  }

  const envBinding = (hub.__env__?.DB as D1Client | undefined) ?? hub.DB
  if (envBinding) {
    return envBinding
  }

  if (typeof hub.hubDatabase === 'function') {
    try {
      const binding = hub.hubDatabase()
      if (binding) {
        return binding
      }
    } catch {
      // NuxtHub will throw if bindings are unavailable; fall through to the final error.
    }
  }

  return null
}

export const tables = fallbackTables

export type DrizzleDatabase = FallbackDrizzleDatabase

let cached: DrizzleDatabase | null = null

export function useDrizzle(): DrizzleDatabase {
  if (cached) {
    return cached
  }

  const binding = resolveDatabaseBinding()
  if (binding) {
    cached = drizzleD1(binding, { schema })
    return cached
  }

  cached = useFallbackDrizzle()
  return cached
}

export type User = typeof schema.users.$inferSelect
