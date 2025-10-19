import { mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

type CacheEntry<T> = {
  cachedAt: string
  data: T
}

export type CacheOptions = {
  ttlMs: number
  forceRefresh?: boolean
  allowStale?: boolean
}

export type CacheResult<T> = {
  data: T
  cacheHit: boolean
  cachedAt: Date | null
  stale: boolean
}

const CACHE_DIR = join(process.cwd(), 'data', 'cache')

const ensureCacheDir = async () => {
  await mkdir(CACHE_DIR, { recursive: true })
}

const loadCacheEntry = async <T>(filePath: string): Promise<CacheEntry<T> | null> => {
  try {
    const raw = await readFile(filePath, 'utf8')
    const parsed = JSON.parse(raw) as CacheEntry<T> | null
    if (!parsed || typeof parsed !== 'object' || parsed.data === undefined) {
      return null
    }
    return parsed
  } catch {
    return null
  }
}

const resolveCachedAt = async (entry: CacheEntry<unknown> | null, filePath: string): Promise<number | null> => {
  if (entry?.cachedAt) {
    const parsed = Date.parse(entry.cachedAt)
    if (!Number.isNaN(parsed)) {
      return parsed
    }
  }

  try {
    const details = await stat(filePath)
    return details.mtime.getTime()
  } catch {
    return null
  }
}

export const getCachedData = async <T>(
  key: string,
  fetcher: () => Promise<T>,
  options: CacheOptions
): Promise<CacheResult<T>> => {
  const { ttlMs, forceRefresh = false, allowStale = false } = options
  const cachePath = join(CACHE_DIR, `${key}.json`)

  if (!forceRefresh) {
    const entry = await loadCacheEntry<T>(cachePath)
    if (entry) {
      const cachedAtMs = await resolveCachedAt(entry, cachePath)
      if (cachedAtMs !== null) {
        const age = Date.now() - cachedAtMs
        const isFresh = age <= ttlMs
        if (isFresh || allowStale) {
          return {
            data: entry.data,
            cacheHit: true,
            cachedAt: new Date(cachedAtMs),
            stale: !isFresh
          }
        }
      } else if (allowStale) {
        return {
          data: entry.data,
          cacheHit: true,
          cachedAt: null,
          stale: true
        }
      }
    }
  }

  const data = await fetcher()
  const cachedAt = new Date()

  await ensureCacheDir()
  const entry: CacheEntry<T> = {
    cachedAt: cachedAt.toISOString(),
    data
  }
  await writeFile(cachePath, JSON.stringify(entry), 'utf8')

  return {
    data,
    cacheHit: false,
    cachedAt,
    stale: false
  }
}
