import { mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export type CacheEntry<T> = {
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

const cachePathForKey = (key: string) => join(CACHE_DIR, `${key}.json`)

const ensureCacheDir = async () => {
  await mkdir(CACHE_DIR, { recursive: true })
}

export const loadCacheEntry = async <T>(key: string): Promise<CacheEntry<T> | null> => {
  const filePath = cachePathForKey(key)
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

export const saveCacheEntry = async <T>(key: string, data: T): Promise<CacheEntry<T>> => {
  await ensureCacheDir()
  const entry: CacheEntry<T> = {
    cachedAt: new Date().toISOString(),
    data
  }
  await writeFile(cachePathForKey(key), JSON.stringify(entry), 'utf8')
  return entry
}

export const getCachedData = async <T>(
  key: string,
  fetcher: () => Promise<T>,
  options: CacheOptions
): Promise<CacheResult<T>> => {
  const { ttlMs, forceRefresh = false, allowStale = false } = options
  const cachePath = cachePathForKey(key)

  if (!forceRefresh) {
    const entry = await loadCacheEntry<T>(key)
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
  const entry = await saveCacheEntry(key, data)
  const cachedAt = new Date(entry.cachedAt)

  return {
    data,
    cacheHit: false,
    cachedAt,
    stale: false
  }
}

export const getCacheEntryInfo = async (
  key: string
): Promise<{ cachedAt: Date } | null> => {
  const cachePath = cachePathForKey(key)

  try {
    const details = await stat(cachePath)
    return { cachedAt: details.mtime }
  } catch {
    return null
  }
}
