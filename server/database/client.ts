import Database from 'better-sqlite3'
import type { Database as SqliteDatabase } from 'better-sqlite3'
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
import { migrate } from 'drizzle-orm/better-sqlite3/migrator'
import { existsSync, mkdirSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import * as schema from './schema'

let sqliteInstance: SqliteDatabase | null = null
let drizzleInstance: BetterSQLite3Database<typeof schema> | null = null
let migrationsApplied = false

const DB_FILENAME = 'db.sqlite'
const MIGRATIONS_FOLDER = join(process.cwd(), 'server', 'database', 'migrations')

const ensureDirectory = (filepath: string) => {
  const directory = dirname(filepath)
  if (!existsSync(directory)) {
    mkdirSync(directory, { recursive: true })
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

  const sqlite = initialiseDatabase()
  const db = drizzle(sqlite, { schema })
  drizzleInstance = db

  if (!migrationsApplied) {
    migrate(db, { migrationsFolder: MIGRATIONS_FOLDER })
    migrationsApplied = true
  }

  return db
}

export const useDrizzle = (): BetterSQLite3Database<typeof schema> => initialiseDrizzle()

export const tables = schema

export const resetDatabase = () => {
  if (sqliteInstance) {
    sqliteInstance.close()
    sqliteInstance = null
  }

  drizzleInstance = null
  migrationsApplied = false

  const databasePath = join(process.cwd(), 'data', DB_FILENAME)
  if (existsSync(databasePath)) {
    rmSync(databasePath)
  }
}
