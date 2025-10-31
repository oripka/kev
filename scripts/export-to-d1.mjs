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

const DEFAULT_SYNC_MODE = 'incremental'

const normalizeSyncMode = (value, context) => {
  if (!value) {
    return null
  }

  const normalised = String(value).trim().toLowerCase()
  if (normalised === 'incremental') {
    return 'incremental'
  }
  if (normalised === 'full' || normalised === 'reset' || normalised === 'drop') {
    return 'full'
  }

  throw new Error(
    `Unsupported sync mode "${value}" from ${context}. Expected incremental or full.`
  )
}

const parseCliOptions = () => {
  const args = process.argv.slice(2)
  let syncMode = normalizeSyncMode(process.env.NUXTHUB_D1_SYNC_MODE, 'NUXTHUB_D1_SYNC_MODE env') || DEFAULT_SYNC_MODE
  let usePreview = false

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]

    if (arg === '--') {
      continue
    }

    if (arg === '--preview') {
      usePreview = true
      continue
    }

    if (arg === '--remote') {
      usePreview = false
      continue
    }

    if (arg === '--incremental') {
      syncMode = 'incremental'
      continue
    }

    if (arg === '--full' || arg === '--reset' || arg === '--drop') {
      syncMode = 'full'
      continue
    }

    if (arg === '--mode') {
      const next = args[index + 1]
      if (!next || next.startsWith('--')) {
        throw new Error('Missing value for --mode option')
      }
      const resolved = normalizeSyncMode(next, '--mode option')
      if (resolved) {
        syncMode = resolved
      }
      index += 1
      continue
    }

    if (arg.startsWith('--mode=')) {
      const [, rawValue] = arg.split('=', 2)
      const resolved = normalizeSyncMode(rawValue, '--mode option')
      if (resolved) {
        syncMode = resolved
      }
      continue
    }
  }

  return { usePreview, syncMode }
}

const { usePreview, syncMode } = parseCliOptions()
const wranglerTargetFlag = usePreview ? '--preview' : '--remote'
const isIncrementalSync = syncMode === 'incremental'

const wait = (milliseconds) => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds)
}

const DEFAULT_WRANGLER_RETRY_ATTEMPTS = 4
const DEFAULT_WRANGLER_RETRY_DELAY_MS = 5_000

const normalizeOutput = (value) => {
  if (!value) {
    return ''
  }
  if (Buffer.isBuffer(value)) {
    return value.toString()
  }
  return String(value)
}

const runWranglerCommand = (
  command,
  {
    label = 'wrangler command',
    maxAttempts = DEFAULT_WRANGLER_RETRY_ATTEMPTS,
    retryDelayMs = DEFAULT_WRANGLER_RETRY_DELAY_MS
  } = {}
) => {
  const resolvedAttempts = Math.max(1, Number(maxAttempts) || 1)
  const resolvedDelay = Math.max(0, Number(retryDelayMs) || 0)

  for (let attempt = 1; attempt <= resolvedAttempts; attempt += 1) {
    try {
      const result = execSync(command, { stdio: 'pipe', cwd: projectRoot })
      const output = normalizeOutput(result)
      if (output) {
        process.stdout.write(output)
      }
      return
    } catch (error) {
      const stdout = normalizeOutput(error?.stdout)
      const stderr = normalizeOutput(error?.stderr)
      if (stdout) {
        process.stdout.write(stdout)
      }
      if (stderr) {
        process.stderr.write(stderr)
      }

      const combined = `${stdout}\n${stderr}\n${normalizeOutput(error?.message)}`
      if (combined.includes('D1_RESET_DO')) {
        if (attempt >= resolvedAttempts) {
          throw error
        }
        logger.warn(
          `Wrangler reported a D1_RESET_DO response while ${label}. Waiting ${(resolvedDelay / 1000).toFixed(
            1
          )}s before retry ${attempt + 1}/${resolvedAttempts}…`
        )
        if (resolvedDelay > 0) {
          wait(resolvedDelay)
        }
        continue
      }

      throw error
    }
  }
}

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

const applyIncrementalTransforms = (content) =>
  content
    .split('\n')
    .map((line) => {
      const trimmed = line.trimStart()
      if (!trimmed) {
        return line
      }

      if (/^CREATE\s+TABLE\s+/i.test(trimmed) && !/CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS/i.test(trimmed)) {
        return line.replace(/^(\s*)CREATE\s+TABLE\s+/i, '$1CREATE TABLE IF NOT EXISTS ')
      }

      if (/^CREATE\s+UNIQUE\s+INDEX\s+/i.test(trimmed) && !/CREATE\s+UNIQUE\s+INDEX\s+IF\s+NOT\s+EXISTS/i.test(trimmed)) {
        return line.replace(/^(\s*)CREATE\s+UNIQUE\s+INDEX\s+/i, '$1CREATE UNIQUE INDEX IF NOT EXISTS ')
      }

      if (/^CREATE\s+INDEX\s+/i.test(trimmed) && !/CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS/i.test(trimmed)) {
        return line.replace(/^(\s*)CREATE\s+INDEX\s+/i, '$1CREATE INDEX IF NOT EXISTS ')
      }

      if (/^INSERT\s+INTO\s+/i.test(trimmed) && !/^INSERT\s+OR\s+/i.test(trimmed)) {
        return line.replace(/^(\s*)INSERT\s+INTO\s+/i, '$1INSERT OR REPLACE INTO ')
      }

      return line
    })
    .join('\n')

const transformDumpForMode = (content, mode) => {
  if (mode === 'incremental') {
    return applyIncrementalTransforms(content)
  }
  return content
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
  runWranglerCommand(
    `npx wrangler d1 execute ${REMOTE_DB} ${wranglerTargetFlag} --yes --file "${resetPath}"`,
    { label: 'resetting the remote database' }
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

const prepareDumpFile = (mode) => {
  logger.start('Cleaning dump file for D1 compatibility …')
  const raw = readFileSync(dumpPath, 'utf8')
  const cleaned = cleanDump(raw)
  const transformed = transformDumpForMode(cleaned, mode)
  writeFileSync(dumpPath, `${transformed}\n`, 'utf8')
  if (mode === 'incremental') {
    logger.success('Dump file prepared for incremental upsert mode.')
  } else {
    logger.success('Dump file cleaned for full refresh mode.')
  }
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

const buildVulnerabilityEntryStatements = (localDbPath, mode) => {
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
      const insertVerb = mode === 'incremental' ? 'INSERT OR REPLACE' : 'INSERT'
      const insertStatement = `${insertVerb} INTO vulnerability_entries (${columnList}) VALUES (${insertValues.join(', ')});`
      statements.push(insertStatement)
      statements.push(...updates)
    }

    return statements
  } finally {
    db.close()
  }
}

const rewriteVulnerabilityEntriesDump = (localDbPath, mode) => {
  logger.start('Rewriting vulnerability_entries export for D1 statement limits …')

  const raw = readFileSync(dumpPath, 'utf8')
  const parsedStatements = splitSqlStatements(raw)
  const filteredStatements = parsedStatements.filter((statement) => {
    const normalized = statement.trimStart()
    if (
      /^INSERT\s+(?:OR\s+\w+\s+)?INTO\s+"?vulnerability_entries"?/i.test(normalized)
    ) {
      return false
    }
    if (normalized.startsWith('UPDATE "vulnerability_entries" SET')) {
      return false
    }
    if (normalized.startsWith('UPDATE vulnerability_entries SET')) {
      return false
    }
    if (normalized.startsWith('-- Exported vulnerability_entries')) {
      return false
    }
    return true
  })

  writeFileSync(dumpPath, `${filteredStatements.join('\n')}\n`, 'utf8')

  const entryStatements = buildVulnerabilityEntryStatements(localDbPath, mode)
  if (!entryStatements.length) {
    logger.warn('No vulnerability_entries rows found to export.')
    return
  }

  const header = '\n-- Exported vulnerability_entries with chunked large columns\n'
  appendFileSync(dumpPath, header + entryStatements.join('\n') + '\n', 'utf8')
  const rowInsertCount = entryStatements.filter((line) =>
    /^\s*INSERT\s+(?:OR\s+REPLACE\s+)?INTO\s+vulnerability_entries/i.test(line)
  ).length
  logger.success(`Exported ${rowInsertCount.toLocaleString()} vulnerability_entries rows.`)
}

const chunkDump = () => {
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

  return chunks
}

const uploadChunks = (chunks) => {
  if (!Array.isArray(chunks) || chunks.length === 0) {
    throw new Error('No chunk files available for upload. Aborting export before touching remote database.')
  }

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
    runWranglerCommand(
      `npx wrangler d1 execute ${REMOTE_DB} ${wranglerTargetFlag} --yes --file "${chunkPath}"`,
      { label: `uploading ${chunkPath}` }
    )
    if (chunks.length > 1 && index < chunks.length - 1) {
      uploadProgress.update('   waiting 3s before next chunk to avoid rate limits…', {
        append: true
      })
      wait(3000)
    }
  }

  uploadProgress.succeed('Cloudflare D1 upload complete.')
}

const main = () => {
  try {
    ensureDataDir()
    logger.info(
      syncMode === 'full'
        ? 'Running in FULL reset mode (remote tables will be dropped before import).'
        : 'Running in INCREMENTAL mode (remote tables will be upserted without dropping data).'
    )
    logger.info(`Cloudflare D1 target: ${usePreview ? 'preview' : 'remote production'}`)
    if (!isIncrementalSync) {
      writeResetSql()
    }
    const localDbPath = resolveLocalDatabasePath()
    logger.info(`Using local NuxtHub D1 database at ${localDbPath}`)
    exportLocalDatabase(localDbPath)
    prepareDumpFile(syncMode)
    rewriteVulnerabilityEntriesDump(localDbPath, syncMode)
    const chunks = chunkDump()
    if (isIncrementalSync) {
      logger.info(
        'Incremental mode selected; skipping remote DROP statements and applying INSERT OR REPLACE upserts.'
      )
    } else {
      resetRemoteDatabase()
    }
    uploadChunks(chunks)
    if (isIncrementalSync) {
      logger.success('Remote D1 database updated incrementally.')
    } else {
      logger.success('Remote D1 database refreshed successfully.')
    }
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
