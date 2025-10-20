import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler } from 'h3'
import { getMetadata } from '../../utils/sqlite'

type ImportSourceStatus = {
  key: string
  label: string
  catalogVersion: string | null
  dateReleased: string | null
  lastImportedAt: string | null
  cachedAt: string | null
  totalCount: number | null
}

type ImportStatusResponse = {
  sources: ImportSourceStatus[]
}

const CACHE_DIR = join(process.cwd(), 'data', 'cache')

const normaliseString = (value: string | null): string | null => {
  if (!value) {
    return null
  }

  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

const parseNumber = (value: string | null): number | null => {
  if (!value) {
    return null
  }

  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

const loadCachedAt = async (fileName: string): Promise<string | null> => {
  try {
    const filePath = join(CACHE_DIR, fileName)
    const raw = await readFile(filePath, 'utf8')
    const parsed = JSON.parse(raw) as { cachedAt?: unknown } | null
    const cachedAt = typeof parsed?.cachedAt === 'string' ? parsed.cachedAt : null
    return cachedAt && cachedAt.length > 0 ? cachedAt : null
  } catch {
    return null
  }
}

export default defineEventHandler(async (): Promise<ImportStatusResponse> => {
  const [kevCachedAt, enisaCachedAt] = await Promise.all([
    loadCachedAt('kev-feed.json'),
    loadCachedAt('enisa-feed.json')
  ])

  const kevEntryCount = parseNumber(getMetadata('entryCount') ?? getMetadata('catalog.entryCount'))

  return {
    sources: [
      {
        key: 'kev',
        label: 'CISA KEV catalog',
        catalogVersion: normaliseString(getMetadata('catalogVersion')),
        dateReleased: normaliseString(getMetadata('dateReleased')),
        lastImportedAt: normaliseString(getMetadata('lastImportAt')),
        cachedAt: kevCachedAt,
        totalCount: kevEntryCount
      },
      {
        key: 'enisa',
        label: 'ENISA exploited catalog',
        catalogVersion: normaliseString(getMetadata('enisa.lastUpdatedAt')),
        dateReleased: null,
        lastImportedAt: normaliseString(getMetadata('enisa.lastImportAt')),
        cachedAt: enisaCachedAt,
        totalCount: parseNumber(getMetadata('enisa.totalCount'))
      },
      {
        key: 'historic',
        label: 'Historic exploit dataset',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: normaliseString(getMetadata('historic.lastImportAt')),
        cachedAt: null,
        totalCount: parseNumber(getMetadata('historic.totalCount'))
      }
    ]
  }
})
