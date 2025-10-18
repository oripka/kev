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
