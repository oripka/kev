import Database from 'better-sqlite3'
import type { Database as SqliteDatabase } from 'better-sqlite3'
import { drizzle as drizzleSqlite, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
import { drizzle as drizzleD1, type DrizzleD1Database } from 'drizzle-orm/d1'
import { migrate } from 'drizzle-orm/better-sqlite3/migrator'
import { readMigrationFiles } from 'drizzle-orm/migrator'
import { existsSync, mkdirSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import * as schema from './schema'

let sqliteInstance: SqliteDatabase | null = null
let drizzleInstance: DrizzleDatabase | null = null
let migrationsApplied = false

const DB_FILENAME = 'db.sqlite'
const MIGRATIONS_FOLDER = join(process.cwd(), 'server', 'database', 'migrations')

type D1Client = Parameters<typeof drizzleD1>[0]

type HubGlobal = typeof globalThis & {
  hubDatabase?: () => D1Client
  __env__?: Record<string, unknown>
  DB?: D1Client
}

const resolveDatabaseBinding = (): D1Client | null => {
  const hub = globalThis as HubGlobal
  const binding =
    (typeof process !== 'undefined' && (process.env.DB as D1Client | undefined)) ||
    (hub.__env__?.DB as D1Client | undefined) ||
    hub.DB

  return binding ?? null
}

type SqliteDrizzleDatabase = BetterSQLite3Database<typeof schema>
type D1DrizzleDatabase = DrizzleD1Database<typeof schema>

export type DrizzleDatabase = SqliteDrizzleDatabase | D1DrizzleDatabase

const resolveHubDatabase = (): D1Client | null => {
  const directBinding = resolveDatabaseBinding()
  if (directBinding) {
    return directBinding
  }

  const hub = (globalThis as HubGlobal).hubDatabase
  if (typeof hub !== 'function') {
    return null
  }

  try {
    return hub()
  } catch {
    return null
  }
}

const ensureBaselineMigrations = (sqlite: SqliteDatabase) => {
  const hasCatalogEntries = sqlite
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get('catalog_entries')

  if (!hasCatalogEntries) {
    return
  }

  sqlite
    .prepare(
      'CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (id INTEGER PRIMARY KEY AUTOINCREMENT, hash text NOT NULL, created_at numeric)'
    )
    .run()

  const migrationCount = sqlite
    .prepare('SELECT COUNT(*) as count FROM "__drizzle_migrations"')
    .get() as { count: number }

  if (migrationCount.count > 0) {
    return
  }

  const migrations = readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER })
  const insert = sqlite.prepare(
    'INSERT INTO "__drizzle_migrations" ("hash", "created_at") VALUES (?, ?)' 
  )
  const insertTransaction = sqlite.transaction((records: typeof migrations) => {
    for (const migration of records) {
      insert.run(migration.hash, migration.folderMillis)
    }
  })

  insertTransaction(migrations)
}

const ensureDirectory = (filepath: string) => {
  const directory = dirname(filepath)
  try {
    if (!existsSync(directory)) {
      mkdirSync(directory, { recursive: true })
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes('not implemented')) {
      return
    }
    throw error
  }
}

const initialiseDatabase = () => {
  if (sqliteInstance) {
    return sqliteInstance
  }

  const databasePath = join(process.cwd(), 'data', DB_FILENAME)
  ensureDirectory(databasePath)

  const sqlite = new Database(databasePath)
  sqlite.pragma('journal_mode = WAL')
  sqlite.pragma('busy_timeout = 5000')
  sqlite.pragma('foreign_keys = ON')

  sqliteInstance = sqlite
  return sqlite
}

const initialiseDrizzle = () => {
  if (drizzleInstance) {
    return drizzleInstance
  }

  const hubDatabase = resolveHubDatabase()
  if (hubDatabase) {
    const db = drizzleD1(hubDatabase, { schema })
    drizzleInstance = db
    return db
  }

  const sqlite = initialiseDatabase()
  ensureBaselineMigrations(sqlite)
  const db = drizzleSqlite(sqlite, { schema })
  drizzleInstance = db

  if (!migrationsApplied) {
    migrate(db, { migrationsFolder: MIGRATIONS_FOLDER })
    migrationsApplied = true
  }

  return db
}

export const useDrizzle = (): DrizzleDatabase => initialiseDrizzle()

export const tables = schema

export const closeDatabase = () => {
  if (sqliteInstance) {
    sqliteInstance.close()
    sqliteInstance = null
  }

  drizzleInstance = null
  migrationsApplied = false
}

export const resetDatabase = () => {
  closeDatabase()

  const databasePath = join(process.cwd(), 'data', DB_FILENAME)
  if (existsSync(databasePath)) {
    try {
      rmSync(databasePath)
    } catch (error) {
      if (error instanceof Error && error.message.includes('not implemented')) {
        return
      }
      throw error
    }
  }
}
