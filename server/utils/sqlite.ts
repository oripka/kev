import Database from 'better-sqlite3'
import type { Database as SqliteDatabase } from 'better-sqlite3'
import { existsSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'

let instance: SqliteDatabase | null = null

const MIGRATIONS = `
CREATE TABLE IF NOT EXISTS kev_entries (
  cve_id TEXT PRIMARY KEY,
  vendor TEXT,
  product TEXT,
  vulnerability_name TEXT,
  description TEXT,
  required_action TEXT,
  date_added TEXT,
  due_date TEXT,
  ransomware_use TEXT,
  notes TEXT,
  cwes TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  cvss_version TEXT,
  cvss_severity TEXT,
  domain_categories TEXT,
  exploit_layers TEXT,
  vulnerability_categories TEXT,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS kev_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

const DB_FILENAME = 'kev.sqlite'

const ensureColumn = (db: SqliteDatabase, table: string, column: string, definition: string) => {
  const columns = db
    .prepare<{ name: string }>(`PRAGMA table_info(${table})`)
    .all() as Array<{ name: string }>

  if (!columns.some(existing => existing.name === column)) {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run()
  }
}

export const getDatabase = () => {
  if (instance) {
    return instance
  }

  const databasePath = join(process.cwd(), 'data', DB_FILENAME)
  const directory = dirname(databasePath)

  if (!existsSync(directory)) {
    mkdirSync(directory, { recursive: true })
  }

  instance = new Database(databasePath)
  instance.pragma('journal_mode = WAL')
  instance.pragma('busy_timeout = 5000')
  instance.exec(MIGRATIONS)

  ensureColumn(instance, 'kev_entries', 'cvss_score', 'REAL')
  ensureColumn(instance, 'kev_entries', 'cvss_vector', 'TEXT')
  ensureColumn(instance, 'kev_entries', 'cvss_version', 'TEXT')
  ensureColumn(instance, 'kev_entries', 'cvss_severity', 'TEXT')

  return instance
}

export const getMetadata = (key: string): string | null => {
  const db = getDatabase()
  const statement = db.prepare<{ value: string }>('SELECT value FROM kev_metadata WHERE key = ? LIMIT 1')
  const row = statement.get(key) as { value: string } | undefined
  return row?.value ?? null
}

export const setMetadata = (key: string, value: string) => {
  const db = getDatabase()
  const statement = db.prepare(
    `INSERT INTO kev_metadata (key, value) VALUES (@key, @value)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  )
  statement.run({ key, value })
}
