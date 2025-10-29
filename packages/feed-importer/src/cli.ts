#!/usr/bin/env node
import process from 'node:process'
import { spawn } from 'node:child_process'
import ansis from 'ansis'
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
import { logger } from './logger'

const USAGE = `Usage: pnpm run import-feeds [--mode <auto|force|cache>] [--source <name|all>] [--strategy <full|incremental>]

Options:
  --mode       Import mode controlling cache behaviour (default: auto)
  --source     Comma-separated list of sources to import (kev, historic, enisa, metasploit, poc, market) or "all"
  --strategy   Import strategy to use (full or incremental)
  --incremental  Shortcut for --strategy incremental
  --full         Shortcut for --strategy full
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
      logger.log(USAGE)
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

    if (key === '--incremental') {
      if (rawValue && rawValue.trim() && rawValue.trim().toLowerCase() !== 'true') {
        throw new Error('The --incremental flag does not accept a value')
      }
      options.set('--strategy', 'incremental')
      continue
    }

    if (key === '--full') {
      if (rawValue && rawValue.trim() && rawValue.trim().toLowerCase() !== 'true') {
        throw new Error('The --full flag does not accept a value')
      }
      options.set('--strategy', 'full')
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

const STATUS_STYLES: Record<EventStatusKey, (value: string) => string> = {
  info: ansis.cyan,
  pending: ansis.yellow,
  running: ansis.blue,
  complete: ansis.green,
  skipped: ansis.dim,
  error: ansis.red
}

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
      const phaseLabel = ansis.bold(ansis.magenta(`Phase ${progress.phase}`))
      const totals = ansis.yellow(totalLabel)
      const summary = `${phaseLabel}${ansis.dim(' · ')}${totals}` +
        (progress.message ? `${ansis.dim(' · ')}${progress.message}` : '')
      if (summary !== lastSummary) {
        logger.progress(summary, { mode: 'update' })
        lastSummary = summary
      }
    } else if (lastSummary) {
      logger.endProgress()
      lastSummary = ''
    }

    for (const event of progress.events) {
      if (!event.id || seenEvents.has(event.id)) {
        continue
      }
      seenEvents.add(event.id)

      const status = (event.status ?? 'info') as EventStatusKey
      const statusLabel = EVENT_STATUS_LABELS[status] ?? EVENT_STATUS_LABELS.info
      const formatter = STATUS_STYLES[status] ?? STATUS_STYLES.info
      const formattedStatus = formatter(`[${statusLabel}]`)
      const taskLabel = event.taskLabel ? `${ansis.bold(`${event.taskLabel}:`)} ` : ''
      logger.progress(`  ${formattedStatus} ${taskLabel}${event.message}`, { mode: 'append' })
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
      logger.endProgress()
    }
  }
}

const main = async () => {
  const reporter = createProgressReporter()

  try {
    const { mode, sources, strategy, syncD1 } = parseCliArgs()
    const db = useDrizzle()

    logger.info(ansis.bold(ansis.cyan('🚀 Starting vulnerability catalog import')))
    logger.info(`${ansis.dim(' Mode')}: ${ansis.white(mode)}`)
    logger.info(
      `${ansis.dim(' Strategy')}: ${
        strategy === 'incremental' ? ansis.yellow(strategy) : ansis.white(strategy)
      }`
    )
    logger.info(`${ansis.dim(' Sources')}: ${ansis.white(sources.join(', '))}`)
    logger.info(`${ansis.dim(' Sync D1')}: ${syncD1 ? ansis.green('enabled') : ansis.dim('disabled')}`)
    logger.log(ansis.dim('----------------------------------------'))

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
      logger.newline()
      logger.info(ansis.bold('🔄 Syncing remote D1 database from local SQLite export …'))
      logger.info(ansis.dim('   Running pnpm run db:deploy'))
      await runCommand('pnpm', ['run', 'db:deploy'])
      logger.success(ansis.green('   Remote D1 database synced successfully.'))
      logger.newline()
    }

    const summaryParts = [
      `${ansis.bold(formatNumber(result.imported))} total entries`,
      `${ansis.bold(formatNumber(result.kevImported))} KEV`,
      `${ansis.bold(formatNumber(result.historicImported))} historic`,
      `${ansis.bold(formatNumber(result.enisaImported))} ENISA`,
      `${ansis.bold(formatNumber(result.metasploitImported))} Metasploit`,
      `${ansis.bold(formatNumber(result.pocImported))} GitHub PoCs`,
      `${ansis.bold(formatNumber(result.marketOfferCount))} market offers`
    ]

    const summaryLabel = summaryParts.join(ansis.dim(' · '))

    logger.newline()
    logger.success(ansis.bold(ansis.green('✅ Import completed successfully')))
    logger.info(`${ansis.dim('  Sources')}: ${ansis.cyan(result.sources.join(', '))}`)
    logger.info(`${ansis.dim('  Catalog version')}: ${ansis.white(result.catalogVersion || 'unknown')}`)
    logger.info(`${ansis.dim('  Date released')}: ${ansis.white(result.dateReleased || 'unknown')}`)
    logger.info(`${ansis.dim('  Imported at')}: ${ansis.white(result.importedAt)}`)
    logger.info(`${ansis.dim('  Summary')}: ${summaryLabel}`)
  } catch (error) {
    logger.newline()
    logger.error(ansis.bold(ansis.red('❌ Import failed')))
    if (error instanceof CatalogImportError) {
      logger.error(`  ${ansis.red(error.message)}`)
      if (error.details) {
        logger.error(`  ${ansis.red(`Details: ${JSON.stringify(error.details)}`)}`)
      }
    } else if (error instanceof Error) {
      logger.error(`  ${ansis.red(error.message)}`)
    } else {
      logger.error(`  ${ansis.red('An unknown error occurred')}`)
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
