#!/usr/bin/env node

import { execSync } from 'node:child_process'
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import Database from 'better-sqlite3'

import { createCliLogger } from './utils/logger.mjs'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const projectRoot = resolve(__dirname, '..')
const dataDir = join(projectRoot, 'data')

const REMOTE_DB = process.env.NUXTHUB_D1_DATABASE || 'kev'
const dumpFilename =
  process.env.NUXTHUB_D1_DUMP ||
  'fe68a0d1-ca7f-4907-8581-e0960e2a420f.sql'
const dumpPath = join(dataDir, dumpFilename)
const resetPath = join(dataDir, 'reset-d1.sql')
const chunkDir = join(dataDir, 'dump-chunks')
const hubD1Dir = join(projectRoot, '.data', 'hub', 'd1')
const legacyLocalDbPath = join(dataDir, 'db.sqlite')

const logger = createCliLogger({ tag: 'export-to-d1' })

const usePreview = process.argv.includes('--preview')
const wranglerTargetFlag = usePreview ? '--preview' : '--remote'

const INCLUDED_TABLES = [
  '__drizzle_migrations',
  'catalog_entries',
  'catalog_entry_dimensions',
  'product_catalog',
  'market_offers',
  'market_offer_targets',
  'market_offer_categories',
  'market_programs',
  'vulnerability_entries',
  'kev_metadata',
  'user_sessions',
  'user_product_filters'
]

const dropOrder = [
  'catalog_entry_dimensions',
  'market_offer_categories',
  'market_offer_metrics',
  'market_offer_targets',
  'market_program_snapshots',
  'market_offers',
  'vulnerability_entry_categories',
  'vulnerability_entry_impacts',
  'user_product_filters',
  'catalog_entries',
  'market_programs',
  'product_catalog',
  'user_sessions',
  'vulnerability_entries',
  'kev_metadata',
  '__drizzle_migrations'
]

const decodeUnicodeEscapes = (value) =>
  value.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  )

const escapeSqlString = (value) => value.replace(/'/g, "''")

const replaceUnistrCalls = (line) =>
  line.replace(/unistr\('((?:[^']|'')*)'\)/gi, (_, inner) => {
    const withSingles = inner.replace(/''/g, "'")
    const decoded = decodeUnicodeEscapes(withSingles)
    const reescaped = escapeSqlString(decoded)
    return `'${reescaped}'`
  })

const cleanDump = (content) => {
  const forbiddenPrefixes = [
    'BEGIN TRANSACTION;',
    'COMMIT;',
    'PRAGMA',
    '--',
    '/*',
    '*/'
  ]
  return content
    .split('\n')
    .map((line) => replaceUnistrCalls(line))
    .filter((line) => {
      const trimmed = line.trim()
      if (trimmed.length === 0) {
        return false
      }
      if (
        forbiddenPrefixes.some((prefix) => trimmed.startsWith(prefix))
      ) {
        return false
      }
      if (trimmed.includes('sqlite_sequence')) {
        return false
      }
      return true
    })
    .join('\n')
}

const VULNERABILITY_ENTRY_COLUMNS = [
  'id',
  'cve_id',
  'source',
  'vendor',
  'product',
  'vendor_key',
  'product_key',
  'vulnerability_name',
  'description',
  'required_action',
  'date_added',
  'due_date',
  'ransomware_use',
  'notes',
  'cwes',
  'cvss_score',
  'cvss_vector',
  'cvss_version',
  'cvss_severity',
  'epss_score',
  'assigner',
  'date_published',
  'date_updated',
  'exploited_since',
  'source_url',
  'poc_url',
  'poc_published_at',
  'reference_links',
  'aliases',
  'affected_products',
  'problem_types',
  'metasploit_module_path',
  'metasploit_module_published_at',
  'internet_exposed',
  'updated_at'
]

const LARGE_TEXT_COLUMNS = new Set([
  'description',
  'notes',
  'cwes',
  'reference_links',
  'aliases',
  'affected_products',
  'problem_types'
])

const LARGE_COLUMN_THRESHOLD = 40_000
const LARGE_COLUMN_CHUNK_SIZE = 40_000

const LARGE_COLUMN_INSERT_FALLBACKS = new Map([
  ['affected_products', '[]'],
  ['problem_types', '[]']
])

const ensureDataDir = () => {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true })
  }
}

const writeResetSql = () => {
  const sql = [
    'PRAGMA foreign_keys = OFF;',
    ...dropOrder.map(
      (table) => `DROP TABLE IF EXISTS ${table};`
    ),
    'PRAGMA foreign_keys = ON;'
  ].join('\n')
  writeFileSync(resetPath, `${sql}\n`, 'utf8')
}

const resetRemoteDatabase = () => {
  logger.start(`Resetting remote D1 database "${REMOTE_DB}"…`)
  execSync(
    `npx wrangler d1 execute ${REMOTE_DB} ${wranglerTargetFlag} --yes --file "${resetPath}"`,
    { stdio: 'inherit', cwd: projectRoot }
  )
  logger.success(`Remote D1 database "${REMOTE_DB}" reset.`)
}

const findSqliteFile = directory => {
  if (!existsSync(directory)) {
    return null
  }

  const entries = readdirSync(directory, { withFileTypes: true })
  for (const entry of entries) {
    const entryPath = join(directory, entry.name)
    if (entry.isDirectory()) {
      const nested = findSqliteFile(entryPath)
      if (nested) {
        return nested
      }
      continue
    }
    if (entry.isFile() && entry.name.endsWith('.sqlite')) {
      return entryPath
    }
  }
  return null
}

const resolveLocalDatabasePath = () => {
  const envPath =
    process.env.NUXTHUB_LOCAL_D1_PATH ||
    process.env.LOCAL_SQLITE_PATH ||
    process.env.DATABASE_PATH
  if (envPath) {
    const resolved = resolve(projectRoot, envPath)
    if (!existsSync(resolved)) {
      throw new Error(`Configured database file not found at ${resolved}`)
    }
    return resolved
  }

  const hubDbFile = findSqliteFile(hubD1Dir)
  if (hubDbFile) {
    return hubDbFile
  }

  if (existsSync(legacyLocalDbPath)) {
    return legacyLocalDbPath
  }

  throw new Error(
    `Unable to locate a NuxtHub D1 database file. Looked under ${hubD1Dir} and ${legacyLocalDbPath}.`
  )
}

const exportLocalDatabase = localDbPath => {
  if (!existsSync(localDbPath)) {
    throw new Error(
      `Local database not found at ${localDbPath}. Run the app locally to generate it or adjust the path.`
    )
  }
  logger.start('Exporting selected tables from local SQLite database via sqlite3 …')
  const dumpArgs = INCLUDED_TABLES.join(' ')
  execSync(
    `sqlite3 "${localDbPath}" ".dump ${dumpArgs}" > "${dumpPath}"`,
    { stdio: 'inherit', shell: '/bin/bash', cwd: projectRoot }
  )
  logger.success(`Exported selected tables to ${dumpPath}.`)
}

const prepareDumpFile = () => {
  logger.start('Cleaning dump file for D1 compatibility …')
  const raw = readFileSync(dumpPath, 'utf8')
  const cleaned = cleanDump(raw)
  writeFileSync(dumpPath, `${cleaned}\n`, 'utf8')
  logger.success('Dump file cleaned for D1 compatibility.')
}

const sqlLiteral = (value) => {
  if (value === null || value === undefined) {
    return 'NULL'
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }
  if (typeof value === 'bigint') {
    return value.toString()
  }
  const stringValue = String(value)
  const escaped = stringValue.replace(/'/g, "''")
  return `'${escaped}'`
}

const chunkString = (value, size) => {
  const chunks = []
  for (let index = 0; index < value.length; index += size) {
    chunks.push(value.slice(index, index + size))
  }
  return chunks
}

const splitSqlStatements = (sql) => {
  const statements = []
  let buffer = ''
  let inString = false
  let quoteChar = ''

  for (let index = 0; index < sql.length; index += 1) {
    const char = sql[index]
    buffer += char

    if (inString) {
      if (char === quoteChar) {
        const nextChar = sql[index + 1]
        if (nextChar === quoteChar) {
          buffer += nextChar
          index += 1
        } else {
          inString = false
          quoteChar = ''
        }
      }
      continue
    }

    if (char === "'" || char === '"') {
      inString = true
      quoteChar = char
      continue
    }

    if (char === ';') {
      const statement = buffer.trim()
      if (statement.length > 0) {
        statements.push(statement)
      }
      buffer = ''
    }
  }

  const trailing = buffer.trim()
  if (trailing.length > 0) {
    statements.push(trailing)
  }

  return statements
}

const buildVulnerabilityEntryStatements = (localDbPath) => {
  const db = new Database(localDbPath, { readonly: true })
  try {
    const hasTable = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vulnerability_entries'")
      .get()

    if (!hasTable) {
      return []
    }

    const selectSql = `SELECT ${VULNERABILITY_ENTRY_COLUMNS.map((column) => `"${column}"`).join(', ')} FROM vulnerability_entries`
    const statement = db.prepare(selectSql)
    const statements = []

    for (const row of statement.iterate()) {
      const insertValues = []
      const updates = []
      const idLiteral = sqlLiteral(row.id)

      for (const column of VULNERABILITY_ENTRY_COLUMNS) {
        const value = row[column]

        if (
          typeof value === 'string' &&
          LARGE_TEXT_COLUMNS.has(column) &&
          value.length > LARGE_COLUMN_THRESHOLD
        ) {
          const fallback = LARGE_COLUMN_INSERT_FALLBACKS.has(column)
            ? sqlLiteral(LARGE_COLUMN_INSERT_FALLBACKS.get(column))
            : sqlLiteral('')
          insertValues.push(fallback)
          const chunks = chunkString(value, LARGE_COLUMN_CHUNK_SIZE)
          if (chunks.length > 0) {
            const [firstChunk, ...remaining] = chunks
            updates.push(`UPDATE vulnerability_entries SET "${column}" = ${sqlLiteral(firstChunk)} WHERE "id" = ${idLiteral};`)
            for (const chunk of remaining) {
              updates.push(
                `UPDATE vulnerability_entries SET "${column}" = "${column}" || ${sqlLiteral(chunk)} WHERE "id" = ${idLiteral};`
              )
            }
          }
        } else {
          insertValues.push(sqlLiteral(value))
        }
      }

      const columnList = VULNERABILITY_ENTRY_COLUMNS.map((column) => `"${column}"`).join(', ')
      const insertStatement = `INSERT INTO vulnerability_entries (${columnList}) VALUES (${insertValues.join(', ')});`
      statements.push(insertStatement)
      statements.push(...updates)
    }

    return statements
  } finally {
    db.close()
  }
}

const rewriteVulnerabilityEntriesDump = (localDbPath) => {
  logger.start('Rewriting vulnerability_entries export for D1 statement limits …')

  const raw = readFileSync(dumpPath, 'utf8')
  const parsedStatements = splitSqlStatements(raw)
  const filteredStatements = parsedStatements.filter((statement) => {
    const normalized = statement.trimStart()
    return !(
      normalized.startsWith('INSERT INTO "vulnerability_entries"') ||
      normalized.startsWith('INSERT INTO vulnerability_entries') ||
      normalized.startsWith('UPDATE "vulnerability_entries" SET') ||
      normalized.startsWith('UPDATE vulnerability_entries SET') ||
      normalized.startsWith('-- Exported vulnerability_entries')
    )
  })

  writeFileSync(dumpPath, `${filteredStatements.join('\n')}\n`, 'utf8')

  const entryStatements = buildVulnerabilityEntryStatements(localDbPath)
  if (!entryStatements.length) {
    logger.warn('No vulnerability_entries rows found to export.')
    return
  }

  const header = '\n-- Exported vulnerability_entries with chunked large columns\n'
  appendFileSync(dumpPath, header + entryStatements.join('\n') + '\n', 'utf8')
  const rowInsertCount = entryStatements.filter((line) => line.startsWith('INSERT INTO vulnerability_entries')).length
  logger.success(`Exported ${rowInsertCount.toLocaleString()} vulnerability_entries rows.`)
}

const uploadDump = () => {
  logger.start('Chunking dump for upload …')
  const sql = readFileSync(dumpPath, 'utf8')
  if (existsSync(chunkDir)) {
    rmSync(chunkDir, { recursive: true, force: true })
  }
  mkdirSync(chunkDir, { recursive: true })

  const defaultChunkBytes = 5 * 1024 * 1024
  let chunkSize = Number(process.env.NUXTHUB_D1_CHUNK_BYTES)
  if (!Number.isFinite(chunkSize) || chunkSize <= 0) {
    chunkSize = defaultChunkBytes
  }

  const chunks = []
  let chunkBuffer = ''
  let chunkBytes = 0
  let statementBuffer = ''
  let inString = false
  let quoteChar = ''

  const flushChunk = () => {
    const trimmed = chunkBuffer.trim()
    if (!trimmed) {
      chunkBuffer = ''
      chunkBytes = 0
      return
    }
    const chunkIndex = String(chunks.length + 1).padStart(3, '0')
    const chunkPath = join(chunkDir, `${chunkIndex}.sql`)
    writeFileSync(chunkPath, `${trimmed}\n`, 'utf8')
    chunks.push(chunkPath)
    chunkBuffer = ''
    chunkBytes = 0
  }

  const writeStatement = (statement) => {
    if (!statement) {
      return
    }
    const normalized = statement.endsWith(';') ? statement : `${statement};`
    const block = `${normalized}\n`
    const blockBytes = Buffer.byteLength(block, 'utf8')

    if (blockBytes > chunkSize) {
      flushChunk()
      const chunkIndex = String(chunks.length + 1).padStart(3, '0')
      const chunkPath = join(chunkDir, `${chunkIndex}.sql`)
      writeFileSync(chunkPath, block, 'utf8')
      chunks.push(chunkPath)
      return
    }

    if (chunkBytes > 0 && chunkBytes + blockBytes > chunkSize) {
      flushChunk()
    }

    chunkBuffer += block
    chunkBytes += blockBytes
  }

  const flushStatementBuffer = () => {
    const trimmed = statementBuffer.trim()
    if (trimmed) {
      writeStatement(trimmed)
    }
    statementBuffer = ''
  }

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i]
    statementBuffer += char

    if (inString) {
      if (char === quoteChar) {
        const nextChar = sql[i + 1]
        if (nextChar === quoteChar) {
          statementBuffer += nextChar
          i += 1
        } else {
          inString = false
          quoteChar = ''
        }
      }
      continue
    }

    if (char === "'" || char === '"') {
      inString = true
      quoteChar = char
      continue
    }

    if (char === ';') {
      flushStatementBuffer()
    }
  }

  flushStatementBuffer()
  flushChunk()

  logger.success(`Chunked dump into ${chunks.length} file(s).`)

  const uploadProgress = logger.progress(
    `Uploading ${chunks.length} chunk(s) to Cloudflare D1 …`,
    { append: false }
  )

  for (const [index, chunkPath] of chunks.entries()) {
    uploadProgress.update(
      `Uploading chunk ${index + 1}/${chunks.length}`,
      { append: false }
    )
    uploadProgress.update(`→ ${chunkPath}`, { append: true })
    execSync(
      `npx wrangler d1 execute ${REMOTE_DB} ${wranglerTargetFlag} --yes --file "${chunkPath}"`,
      { stdio: 'inherit', cwd: projectRoot }
    )
    if (chunks.length > 1 && index < chunks.length - 1) {
      uploadProgress.update('   waiting 3s before next chunk to avoid rate limits…', {
        append: true
      })
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 3000)
    }
  }

  uploadProgress.succeed('Cloudflare D1 upload complete.')
}

const main = () => {
  try {
    ensureDataDir()
    writeResetSql()
    resetRemoteDatabase()
    const localDbPath = resolveLocalDatabasePath()
    logger.info(`Using local NuxtHub D1 database at ${localDbPath}`)
    exportLocalDatabase(localDbPath)
    prepareDumpFile()
    rewriteVulnerabilityEntriesDump(localDbPath)
    uploadDump()
    logger.success('Remote D1 database refreshed successfully.')
  } catch (error) {
    logger.fail('Failed to export local database to D1.')
    if (error instanceof Error) {
      logger.error(error)
    } else {
      logger.error(String(error))
    }
    process.exitCode = 1
  }
}

main()
