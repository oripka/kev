import Database from 'better-sqlite3'
import type { Database as SqliteDatabase } from 'better-sqlite3'
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
import { existsSync, mkdirSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import * as schema from './schema'

let sqliteInstance: SqliteDatabase | null = null
let drizzleInstance: BetterSQLite3Database<typeof schema> | null = null

const DB_FILENAME = 'db.sqlite'

const INITIAL_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS catalog_entries (
  cve_id TEXT PRIMARY KEY,
  entry_id TEXT NOT NULL,
  sources TEXT NOT NULL,
  vendor TEXT NOT NULL,
  vendor_key TEXT NOT NULL,
  product TEXT NOT NULL,
  product_key TEXT NOT NULL,
  vulnerability_name TEXT NOT NULL,
  description TEXT NOT NULL,
  required_action TEXT,
  date_added TEXT,
  date_added_ts INTEGER,
  date_added_year INTEGER,
  due_date TEXT,
  ransomware_use TEXT,
  has_known_ransomware INTEGER NOT NULL DEFAULT 0,
  notes TEXT NOT NULL,
  cwes TEXT NOT NULL,
  cvss_score REAL,
  cvss_vector TEXT,
  cvss_version TEXT,
  cvss_severity TEXT,
  epss_score REAL,
  assigner TEXT,
  date_published TEXT,
  date_updated TEXT,
  date_updated_ts INTEGER,
  exploited_since TEXT,
  source_url TEXT,
  reference_links TEXT NOT NULL,
  aliases TEXT NOT NULL,
  is_well_known INTEGER NOT NULL DEFAULT 0,
  domain_categories TEXT NOT NULL,
  exploit_layers TEXT NOT NULL,
  vulnerability_categories TEXT NOT NULL,
  internet_exposed INTEGER NOT NULL DEFAULT 0,
  has_source_kev INTEGER NOT NULL DEFAULT 0,
  has_source_enisa INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_catalog_entries_vendor_key ON catalog_entries(vendor_key);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_product_key ON catalog_entries(product_key);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_date_added_ts ON catalog_entries(date_added_ts);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_date_updated_ts ON catalog_entries(date_updated_ts);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_cvss_score ON catalog_entries(cvss_score);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_epss_score ON catalog_entries(epss_score);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_is_well_known ON catalog_entries(is_well_known);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_has_known_ransomware ON catalog_entries(has_known_ransomware);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_internet_exposed ON catalog_entries(internet_exposed);

CREATE TABLE IF NOT EXISTS catalog_entry_dimensions (
  cve_id TEXT NOT NULL,
  dimension TEXT NOT NULL,
  value TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (cve_id, dimension, value)
);

CREATE INDEX IF NOT EXISTS idx_catalog_entry_dimensions_dimension_value
  ON catalog_entry_dimensions(dimension, value);

CREATE TABLE IF NOT EXISTS vulnerability_entries (
  id TEXT PRIMARY KEY,
  cve_id TEXT,
  source TEXT NOT NULL,
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
  epss_score REAL,
  assigner TEXT,
  date_published TEXT,
  date_updated TEXT,
  exploited_since TEXT,
  source_url TEXT,
  reference_links TEXT,
  aliases TEXT,
  internet_exposed INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerability_entry_categories (
  entry_id TEXT NOT NULL,
  category_type TEXT NOT NULL,
  value TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (entry_id, category_type, value),
  FOREIGN KEY (entry_id) REFERENCES vulnerability_entries(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_entry_categories_type_value
  ON vulnerability_entry_categories(category_type, value);

CREATE INDEX IF NOT EXISTS idx_vulnerability_entry_categories_entry
  ON vulnerability_entry_categories(entry_id);

CREATE TABLE IF NOT EXISTS kev_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
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
  sqlite.exec(INITIAL_SCHEMA_SQL)

  sqliteInstance = sqlite
  return sqlite
}

const initialiseDrizzle = () => {
  if (drizzleInstance) {
    return drizzleInstance
  }

  const sqlite = initialiseDatabase()
  drizzleInstance = drizzle(sqlite, { schema })
  return drizzleInstance
}

export const useSqlite = (): SqliteDatabase => initialiseDatabase()

export const useDrizzle = (): BetterSQLite3Database<typeof schema> => initialiseDrizzle()

export const tables = schema

export const resetDatabase = () => {
  if (sqliteInstance) {
    sqliteInstance.close()
    sqliteInstance = null
  }
  drizzleInstance = null

  const databasePath = join(process.cwd(), 'data', DB_FILENAME)
  if (existsSync(databasePath)) {
    rmSync(databasePath)
  }
}
