import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { differenceInDays } from 'date-fns'
import { createTaskQueue } from './concurrency'
import { ensureDir, runGit, syncSparseRepo } from './git'

const SOURCE_REPO_URL = 'https://github.com/0xMarcio/cve.git'
const REPO_DIR = join(process.cwd(), 'data', 'cache', 'github-poc-repo')
const CACHE_DIR = join(process.cwd(), 'data', 'cache')
const CACHE_PATH = join(CACHE_DIR, 'github-poc-published.json')
const HISTORY_CONCURRENCY = 4
const DEFAULT_LOOKBACK_DAYS = 365

type PublishCacheRecord = {
  publishedAt: string | null
  cachedAt: string
}

type PublishCache = {
  records: Record<string, PublishCacheRecord>
}

const loadCache = async (): Promise<PublishCache> => {
  try {
    const raw = await readFile(CACHE_PATH, 'utf8')
    const parsed = JSON.parse(raw) as PublishCache | null
    if (!parsed || typeof parsed !== 'object' || !parsed.records) {
      return { records: {} }
    }
    return parsed
  } catch {
    return { records: {} }
  }
}

const persistCache = async (cache: PublishCache) => {
  await ensureDir(CACHE_DIR)
  await writeFile(CACHE_PATH, JSON.stringify(cache, null, 2), 'utf8')
}

const loadRepository = async (useCachedRepository: boolean) => {
  await syncSparseRepo({
    repoUrl: SOURCE_REPO_URL,
    branch: 'main',
    workingDir: REPO_DIR,
    sparsePaths: ['docs/CVE_list.json'],
    useCachedRepository
  })
}

const fetchFirstCommitDate = async (cveId: string): Promise<string | null> => {
  try {
    const result = await runGit(
      [
        'log',
        '--reverse',
        '--format=%cI',
        '--max-count=1',
        '-S',
        cveId,
        '--',
        'docs/CVE_list.json'
      ],
      { cwd: REPO_DIR }
    )

    const timestamp = result.stdout.split('\n').map(line => line.trim()).find(Boolean)
    return timestamp ?? null
  } catch {
    return null
  }
}

type ResolveOptions = {
  useCachedRepository?: boolean
  lookbackDays?: number
  onStatus?: (message: string) => void
  onProgress?: (completed: number, total: number) => void
}

export type PocPublishDateMap = Map<string, string | null>

export const resolvePocPublishDates = async (
  cveIds: Array<{ cveId: string; referenceDate: string | null }>,
  options: ResolveOptions = {}
): Promise<PocPublishDateMap> => {
  if (!cveIds.length) {
    return new Map()
  }

  const lookbackDays = options.lookbackDays ?? DEFAULT_LOOKBACK_DAYS

  const onStatus = options.onStatus
  const onProgress = options.onProgress

  const windowCutoff = new Date()
  windowCutoff.setDate(windowCutoff.getDate() - lookbackDays)

  const cache = await loadCache()
  const missing: string[] = []
  const result = new Map<string, string | null>()
  let cacheHits = 0
  let cacheMisses = 0
  let skippedByWindow = 0

  for (const { cveId, referenceDate } of cveIds) {
    const cached = cache.records[cveId]
    if (cached?.publishedAt) {
      cacheHits += 1
      result.set(cveId, cached.publishedAt)
      continue
    }

    if (cached && cached.publishedAt === null) {
      cacheMisses += 1
      result.set(cveId, null)
      continue
    }

    if (referenceDate) {
      const parsed = new Date(referenceDate)
      if (!Number.isNaN(parsed.getTime())) {
        if (differenceInDays(parsed, windowCutoff) < 0) {
          // Older than the lookback window; treat as not required
          skippedByWindow += 1
          result.set(cveId, null)
          continue
        }
      }
    }

    missing.push(cveId)
  }

  const missingCount = missing.length
  onStatus?.(
    missingCount
      ? `Preparing to resolve ${missingCount.toLocaleString()} GitHub PoC publish dates (${cacheHits.toLocaleString()} cached, ${cacheMisses.toLocaleString()} previously checked, ${skippedByWindow.toLocaleString()} skipped by window)`
      : `All GitHub PoC publish dates resolved from cache (${cacheHits.toLocaleString()} cached, ${cacheMisses.toLocaleString()} previously checked, ${skippedByWindow.toLocaleString()} skipped by window)`
  )

  if (!missing.length) {
    return result
  }

  await loadRepository(options.useCachedRepository ?? false)
  onStatus?.(
    `Synchronized GitHub PoC history repository (${missing.length.toLocaleString()} lookups queued)`
  )

  const runTask = createTaskQueue(HISTORY_CONCURRENCY)
  const totalMissing = missing.length
  let completed = 0
  let gitHits = 0
  let gitMisses = 0
  let cacheDirty = false

  await Promise.all(
    missing.map(cveId =>
      runTask(async () => {
        const publishedAt = await fetchFirstCommitDate(cveId)
        cache.records[cveId] = {
          publishedAt,
          cachedAt: new Date().toISOString()
        }
        cacheDirty = true
        result.set(cveId, publishedAt)
        if (publishedAt) {
          gitHits += 1
        } else {
          gitMisses += 1
        }
        completed += 1
        onProgress?.(completed, totalMissing)
      })
    )
  )

  onStatus?.(
    `GitHub PoC publish history lookups complete (${gitHits.toLocaleString()} found, ${gitMisses.toLocaleString()} with no history)`
  )

  if (cacheDirty) {
    await persistCache(cache)
    onStatus?.('Updated GitHub PoC publish history cache')
  } else {
    onStatus?.('GitHub PoC publish history cache already up to date')
  }

  return result
}
