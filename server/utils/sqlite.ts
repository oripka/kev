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

CREATE TABLE IF NOT EXISTS enisa_entries (
  enisa_id TEXT PRIMARY KEY,
  cve_id TEXT,
  vendor TEXT,
  product TEXT,
  vulnerability_name TEXT,
  description TEXT,
  assigner TEXT,
  date_published TEXT,
  date_updated TEXT,
  exploited_since TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  cvss_version TEXT,
  cvss_severity TEXT,
  epss_score REAL,
  reference_links TEXT,
  aliases TEXT,
  domain_categories TEXT,
  exploit_layers TEXT,
  vulnerability_categories TEXT,
  source_url TEXT,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS product_catalog (
  product_key TEXT PRIMARY KEY,
  product_name TEXT NOT NULL,
  vendor_key TEXT NOT NULL,
  vendor_name TEXT NOT NULL,
  sources TEXT NOT NULL,
  search_terms TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_product_catalog_search ON product_catalog(search_terms);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_product_filters (
  session_id TEXT NOT NULL,
  vendor_key TEXT NOT NULL,
  vendor_name TEXT NOT NULL,
  product_key TEXT NOT NULL,
  product_name TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_id, product_key),
  FOREIGN KEY (session_id) REFERENCES user_sessions(id) ON DELETE CASCADE
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
  ensureColumn(instance, 'kev_entries', 'internet_exposed', 'INTEGER DEFAULT 0')
  ensureColumn(instance, 'kev_entries', 'updated_at', 'TEXT DEFAULT CURRENT_TIMESTAMP')

  ensureColumn(instance, 'enisa_entries', 'cve_id', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'vendor', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'product', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'vulnerability_name', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'description', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'assigner', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'date_published', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'date_updated', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'exploited_since', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'cvss_score', 'REAL')
  ensureColumn(instance, 'enisa_entries', 'cvss_vector', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'cvss_version', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'cvss_severity', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'epss_score', 'REAL')
  ensureColumn(instance, 'enisa_entries', 'reference_links', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'aliases', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'domain_categories', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'exploit_layers', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'vulnerability_categories', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'source_url', 'TEXT')
  ensureColumn(instance, 'enisa_entries', 'internet_exposed', 'INTEGER DEFAULT 0')
  ensureColumn(instance, 'enisa_entries', 'updated_at', 'TEXT DEFAULT CURRENT_TIMESTAMP')

  ensureColumn(instance, 'product_catalog', 'sources', 'TEXT NOT NULL DEFAULT "[\"kev\"]"')
  ensureColumn(instance, 'product_catalog', 'search_terms', 'TEXT NOT NULL DEFAULT ""')

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
