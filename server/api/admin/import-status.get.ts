import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler } from 'h3'
import { getMetadata } from '../../utils/sqlite'
import { requireAdminKey } from '../../utils/adminAuth'
import type { ImportTaskKey } from '~/types'

type ImportSourceStatus = {
  key: string
  label: string
  importKey: ImportTaskKey | null
  catalogVersion: string | null
  dateReleased: string | null
  lastImportedAt: string | null
  cachedAt: string | null
  totalCount: number | null
  programCount: number | null
  latestCaptureAt: string | null
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

export default defineEventHandler(async (event): Promise<ImportStatusResponse> => {
  requireAdminKey(event)

  const [kevCachedAt, enisaCachedAt, pocCachedAt] = await Promise.all([
    loadCachedAt('kev-feed.json'),
    loadCachedAt('enisa-feed.json'),
    loadCachedAt('github-poc-feed.json')
  ])

  const cvelistLastCommit = normaliseString(getMetadata('cvelist.lastCommit'))
  const cvelistLastRefreshAt = normaliseString(getMetadata('cvelist.lastRefreshAt'))
  const kevEntryCount = parseNumber(getMetadata('entryCount') ?? getMetadata('catalog.entryCount'))
  const marketLastImportedAt = normaliseString(getMetadata('market.lastImportAt'))
  const marketCachedAt = normaliseString(getMetadata('market.cachedAt'))
  const marketOfferCount = parseNumber(getMetadata('market.offerCount'))
  const marketProgramCount = parseNumber(getMetadata('market.programCount'))
  const marketLastCaptureAt = normaliseString(getMetadata('market.lastCaptureAt'))

  return {
    sources: [
      {
        key: 'cvelist',
        label: 'CVEList vendor catalogue',
        importKey: null,
        catalogVersion: cvelistLastCommit ? cvelistLastCommit.slice(0, 12) : null,
        dateReleased: null,
        lastImportedAt: cvelistLastRefreshAt,
        cachedAt: cvelistLastRefreshAt,
        totalCount: null,
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'kev',
        label: 'CISA KEV catalog',
        importKey: 'kev',
        catalogVersion: normaliseString(getMetadata('catalogVersion')),
        dateReleased: normaliseString(getMetadata('dateReleased')),
        lastImportedAt: normaliseString(getMetadata('lastImportAt')),
        cachedAt: kevCachedAt,
        totalCount: kevEntryCount,
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'enisa',
        label: 'ENISA exploited catalog',
        importKey: 'enisa',
        catalogVersion: normaliseString(getMetadata('enisa.lastUpdatedAt')),
        dateReleased: null,
        lastImportedAt: normaliseString(getMetadata('enisa.lastImportAt')),
        cachedAt: enisaCachedAt,
        totalCount: parseNumber(getMetadata('enisa.totalCount')),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'historic',
        label: 'Historic exploit dataset',
        importKey: 'historic',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: normaliseString(getMetadata('historic.lastImportAt')),
        cachedAt: null,
        totalCount: parseNumber(getMetadata('historic.totalCount')),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'metasploit',
        label: 'Metasploit',
        importKey: 'metasploit',
        catalogVersion: normaliseString(getMetadata('metasploit.lastCommit')),
        dateReleased: null,
        lastImportedAt: normaliseString(getMetadata('metasploit.lastImportAt')),
        cachedAt: null,
        totalCount: parseNumber(getMetadata('metasploit.totalCount')),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'poc',
        label: 'GitHub PoC feed',
        importKey: 'poc',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: normaliseString(getMetadata('poc.lastImportAt')),
        cachedAt: pocCachedAt ?? normaliseString(getMetadata('poc.cachedAt')),
        totalCount: parseNumber(getMetadata('poc.totalCount')),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'market',
        label: 'Market intelligence dataset',
        importKey: 'market',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: marketLastImportedAt,
        cachedAt: marketCachedAt ?? marketLastCaptureAt,
        totalCount: marketOfferCount,
        programCount: marketProgramCount,
        latestCaptureAt: marketLastCaptureAt
      }
    ]
  }
})
