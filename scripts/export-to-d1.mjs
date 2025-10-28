#!/usr/bin/env node

import { execSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

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
const localDbPath = join(dataDir, 'db.sqlite')

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
  console.info(`Resetting remote D1 database "${REMOTE_DB}"…`)
  execSync(
    `npx wrangler d1 execute ${REMOTE_DB} ${wranglerTargetFlag} --yes --file "${resetPath}"`,
    { stdio: 'inherit', cwd: projectRoot }
  )
}

const exportLocalDatabase = () => {
  if (!existsSync(localDbPath)) {
    throw new Error(
      `Local database not found at ${localDbPath}. Run the app locally to generate it or adjust the path.`
    )
  }
  console.info('Exporting selected tables from local SQLite database via sqlite3 …')
  const dumpArgs = INCLUDED_TABLES.join(' ')
  execSync(
    `sqlite3 "${localDbPath}" ".dump ${dumpArgs}" > "${dumpPath}"`,
    { stdio: 'inherit', shell: '/bin/bash', cwd: projectRoot }
  )
}

const prepareDumpFile = () => {
  console.info('Cleaning dump file for D1 compatibility …')
  const raw = readFileSync(dumpPath, 'utf8')
  const cleaned = cleanDump(raw)
  writeFileSync(dumpPath, `${cleaned}\n`, 'utf8')
}

const uploadDump = () => {
  console.info('Chunking dump for upload …')
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

  console.info(`Uploading ${chunks.length} chunk(s) to Cloudflare D1 …`)

  for (const chunkPath of chunks) {
    console.info(`→ ${chunkPath}`)
    execSync(
      `npx wrangler d1 execute ${REMOTE_DB} ${wranglerTargetFlag} --yes --file "${chunkPath}"`,
      { stdio: 'inherit', cwd: projectRoot }
    )
    if (chunks.length > 1 && chunkPath !== chunks[chunks.length - 1]) {
      console.info('   waiting 3s before next chunk to avoid rate limits…')
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 3000)
    }
  }
}

const main = () => {
  try {
    ensureDataDir()
    writeResetSql()
    resetRemoteDatabase()
    exportLocalDatabase()
    prepareDumpFile()
    uploadDump()
    console.info('✅ Remote D1 database refreshed successfully.')
  } catch (error) {
    console.error('❌ Failed to export local database to D1.')
    if (error instanceof Error) {
      console.error(error.message)
    }
    process.exitCode = 1
  }
}

main()
