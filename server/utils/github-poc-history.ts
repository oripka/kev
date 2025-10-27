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

  const windowCutoff = new Date()
  windowCutoff.setDate(windowCutoff.getDate() - lookbackDays)

  const cache = await loadCache()
  const missing: string[] = []
  const result = new Map<string, string | null>()

  for (const { cveId, referenceDate } of cveIds) {
    const cached = cache.records[cveId]
    if (cached?.publishedAt) {
      result.set(cveId, cached.publishedAt)
      continue
    }

    if (cached && cached.publishedAt === null) {
      result.set(cveId, null)
      continue
    }

    if (referenceDate) {
      const parsed = new Date(referenceDate)
      if (!Number.isNaN(parsed.getTime())) {
        if (differenceInDays(parsed, windowCutoff) < 0) {
          // Older than the lookback window; treat as not required
          result.set(cveId, null)
          continue
        }
      }
    }

    missing.push(cveId)
  }

  if (!missing.length) {
    return result
  }

  await loadRepository(options.useCachedRepository ?? false)

  const runTask = createTaskQueue(HISTORY_CONCURRENCY)

  await Promise.all(
    missing.map(cveId =>
      runTask(async () => {
        const publishedAt = await fetchFirstCommitDate(cveId)
        cache.records[cveId] = {
          publishedAt,
          cachedAt: new Date().toISOString()
        }
        result.set(cveId, publishedAt)
      })
    )
  )

  await persistCache(cache)

  return result
}
