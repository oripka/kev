import { drizzle, type DrizzleD1Database } from 'drizzle-orm/d1'
export { sql, eq, and, or, inArray } from 'drizzle-orm'

import * as schema from '../database/schema'

type D1Client = Parameters<typeof drizzle>[0]

type HubGlobal = typeof globalThis & {
  hubDatabase?: () => D1Client
  __env__?: Record<string, unknown>
  DB?: D1Client
}

const resolveDatabaseBinding = (): D1Client => {
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

  throw new Error('NuxtHub database binding is not available')
}

export const tables = schema

export type DrizzleDatabase = DrizzleD1Database<typeof schema>

let cached: DrizzleDatabase | null = null

export function useDrizzle(): DrizzleDatabase {
  if (cached) {
    return cached
  }

  const binding = resolveDatabaseBinding()
  cached = drizzle(binding, { schema })
  return cached
}

export type User = typeof schema.users.$inferSelect
