#!/usr/bin/env node
import process from 'node:process'
import { spawn } from 'node:child_process'
import {
  runCatalogImport,
  IMPORT_SOURCE_ORDER,
  isImportSourceKey,
  CatalogImportError
} from './runCatalogImport'
import type { CatalogImportMode, CatalogImportOptions } from './runCatalogImport'
import type { ImportTaskKey } from '~/types'
import type { ImportStrategy } from 'server/utils/import-types'
import { useDrizzle, resetDatabase } from 'server/database/client'
import { getImportProgress } from 'server/utils/import-progress'

const USAGE = `Usage: pnpm run import-feeds [--mode <auto|force|cache>] [--source <name|all>] [--strategy <full|incremental>]

Options:
  --mode       Import mode controlling cache behaviour (default: auto)
  --source     Comma-separated list of sources to import (kev, historic, enisa, metasploit, poc, market) or "all"
  --strategy   Import strategy to use (full or incremental)
  --sync-d1    After a successful import, export the local SQLite database to NuxtHub D1 (default: false)
  --help       Show this help message
`

const parseMode = (value: string | undefined): CatalogImportMode => {
  if (!value) return 'auto'
  switch (value) {
    case 'auto':
    case 'force':
    case 'cache':
      return value
    default:
      throw new Error(`Unknown mode "${value}". Expected auto, force, or cache.`)
  }
}

const parseStrategy = (value: string | undefined): ImportStrategy => {
  if (!value) return 'full'
  switch (value) {
    case 'full':
    case 'incremental':
      return value
    default:
      throw new Error(`Unknown strategy "${value}". Expected full or incremental.`)
  }
}

const normaliseSourceList = (value: string | undefined): ImportTaskKey[] => {
  if (!value || value === 'all') {
    return [...IMPORT_SOURCE_ORDER]
  }

  const segments = value
    .split(',')
    .map(segment => segment.trim().toLowerCase())
    .filter(Boolean)

  if (segments.length === 0) {
    return [...IMPORT_SOURCE_ORDER]
  }

  const resolved = new Set<ImportTaskKey>()

  for (const segment of segments) {
    if (!isImportSourceKey(segment)) {
      throw new Error(
        `Unknown source "${segment}". Valid options: ${['all', ...IMPORT_SOURCE_ORDER].join(', ')}`
      )
    }
    resolved.add(segment)
  }

  return [...resolved]
}

const parseCliArgs = () => {
  const args = process.argv.slice(2)
  const options = new Map<string, string | undefined>()

  const storeBooleanFlag = (
    key: string,
    rawValue: string | undefined,
    nextValue: string | undefined
  ): boolean => {
    if (rawValue !== undefined) {
      options.set(key, rawValue)
      return false
    }
    if (!nextValue || nextValue.startsWith('--')) {
      options.set(key, 'true')
      return false
    }
    options.set(key, nextValue)
    return true
  }

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (arg === '--help' || arg === '-h') {
      console.log(USAGE)
      process.exit(0)
    }

    const [key, rawValue] = arg.split('=', 2)
    if (key === '--mode' || key === '--source' || key === '--strategy') {
      if (rawValue !== undefined) {
        options.set(key, rawValue)
        continue
      }
      const next = args[index + 1]
      if (!next || next.startsWith('--')) {
        throw new Error(`Missing value for ${key}`)
      }
      options.set(key, next)
      index += 1
      continue
    }

    if (key === '--sync-d1') {
      const consumedNext = storeBooleanFlag(key, rawValue, args[index + 1])
      if (consumedNext) {
        index += 1
      }
      continue
    }

    throw new Error(`Unknown argument "${arg}"`)
  }

  const mode = parseMode(options.get('--mode'))
  const sources = normaliseSourceList(options.get('--source'))
  const strategy = parseStrategy(options.get('--strategy'))
  const syncD1 = parseBoolean(options.get('--sync-d1'))

  return { mode, sources, strategy, syncD1 }
}

const formatNumber = (value: number) => value.toLocaleString('en-US')

const EVENT_STATUS_LABELS = {
  info: 'info',
  pending: 'pending',
  running: 'running',
  complete: 'done',
  skipped: 'skipped',
  error: 'error'
} as const

type EventStatusKey = keyof typeof EVENT_STATUS_LABELS

const parseBoolean = (value: string | undefined): boolean => {
  if (value === undefined) {
    return false
  }
  const normalised = value.trim().toLowerCase()
  if (normalised === '' || normalised === 'true' || normalised === '1' || normalised === 'yes') {
    return true
  }
  if (normalised === 'false' || normalised === '0' || normalised === 'no') {
    return false
  }
  throw new Error(`Invalid boolean value "${value}" for --sync-d1. Expected true/false.`)
}

const createProgressReporter = () => {
  const seenEvents = new Set<string>()
  let interval: NodeJS.Timeout | null = null
  let lastSummary = ''

  const logSnapshot = () => {
    const progress = getImportProgress()

    if (progress.phase !== 'idle') {
      const totalLabel =
        progress.total > 0 ? `${progress.completed}/${progress.total}` : `${progress.completed}`
      const summary = `Phase ${progress.phase} · ${totalLabel}${progress.message ? ` · ${progress.message}` : ''}`
      if (summary !== lastSummary) {
        console.log(summary)
        lastSummary = summary
      }
    }

    for (const event of progress.events) {
      if (!event.id || seenEvents.has(event.id)) {
        continue
      }
      seenEvents.add(event.id)

      const statusLabel =
        EVENT_STATUS_LABELS[(event.status ?? 'info') as EventStatusKey] ?? EVENT_STATUS_LABELS.info
      const taskLabel = event.taskLabel ? `${event.taskLabel}: ` : ''
      console.log(`  [${statusLabel}] ${taskLabel}${event.message}`)
    }
  }

  return {
    start() {
      if (interval) {
        return
      }
      logSnapshot()
      interval = setInterval(logSnapshot, 1000)
    },
    stop() {
      if (interval) {
        clearInterval(interval)
        interval = null
      }
      logSnapshot()
    }
  }
}

const main = async () => {
  const reporter = createProgressReporter()

  try {
    const { mode, sources, strategy, syncD1 } = parseCliArgs()
    const db = useDrizzle()

    const importOptions: CatalogImportOptions = {
      db,
      sources,
      forceRefresh: mode === 'force',
      allowStale: mode === 'cache',
      strategy
    }

    reporter.start()
    const result = await runCatalogImport(importOptions)
    reporter.stop()

    if (syncD1) {
      console.log('\nSyncing remote D1 database from local SQLite export …')
      await runCommand('pnpm', ['run', 'db:deploy'])
      console.log('Remote D1 database synced successfully.\n')
    }

    const summaryParts = [
      `${formatNumber(result.imported)} total entries`,
      `${formatNumber(result.kevImported)} KEV`,
      `${formatNumber(result.historicImported)} historic`,
      `${formatNumber(result.enisaImported)} ENISA`,
      `${formatNumber(result.metasploitImported)} Metasploit`,
      `${formatNumber(result.pocImported)} GitHub PoCs`,
      `${formatNumber(result.marketOfferCount)} market offers`
    ]

    console.log('Import completed successfully:')
    console.log(`  Sources: ${result.sources.join(', ')}`)
    console.log(`  Catalog version: ${result.catalogVersion || 'unknown'}`)
    console.log(`  Date released: ${result.dateReleased || 'unknown'}`)
    console.log(`  Imported at: ${result.importedAt}`)
    console.log(`  Summary: ${summaryParts.join(' · ')}`)
  } catch (error) {
    console.error('Import failed:')
    if (error instanceof CatalogImportError) {
      console.error(`  ${error.message}`)
      if (error.details) {
        console.error(`  Details: ${JSON.stringify(error.details)}`)
      }
    } else if (error instanceof Error) {
      console.error(`  ${error.message}`)
    } else {
      console.error('  An unknown error occurred')
    }
    process.exitCode = 1
  } finally {
    reporter.stop()
    resetDatabase()
  }
}

void main()

function runCommand(command: string, args: string[]) {
  return new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', cwd: process.cwd() })
    child.on('close', code => {
      if (code === 0) {
        resolve()
      } else {
        reject(new Error(`Command "${command} ${args.join(' ')}" exited with code ${code}`))
      }
    })
    child.on('error', reject)
  })
}
