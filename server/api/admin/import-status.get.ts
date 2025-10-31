import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler } from 'h3'
import { requireAdminKey } from '../../utils/adminAuth'
import { getMetadataMap } from '../../utils/metadata'
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

type KevImportSummary = {
  lastImportedAt: string | null
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: 'full' | 'incremental'
}

type ImportStatusResponse = {
  sources: ImportSourceStatus[]
  kevSummary: KevImportSummary | null
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

  const metadataKeys = [
    'cvelist.lastCommit',
    'cvelist.lastRefreshAt',
    'entryCount',
    'catalog.entryCount',
    'lastImportAt',
    'kev.lastNewCount',
    'kev.lastUpdatedCount',
    'kev.lastSkippedCount',
    'kev.lastRemovedCount',
    'kev.lastImportStrategy',
    'market.lastImportAt',
    'market.cachedAt',
    'market.offerCount',
    'market.programCount',
    'market.lastCaptureAt',
    'catalogVersion',
    'dateReleased',
    'enisa.lastUpdatedAt',
    'enisa.lastImportAt',
    'enisa.totalCount',
    'epss.lastImportAt',
    'epss.cachedAt',
    'epss.totalCount',
    'epss.lastScoreDate',
    'epss.lastModelVersion',
    'epss.lastNewCount',
    'epss.lastUpdatedCount',
    'epss.lastSkippedCount',
    'epss.lastRemovedCount',
    'epss.lastImportStrategy',
    'historic.lastImportAt',
    'historic.totalCount',
    'custom.lastImportAt',
    'custom.totalCount',
    'metasploit.lastCommit',
    'metasploit.lastImportAt',
    'metasploit.totalCount',
    'poc.lastImportAt',
    'poc.cachedAt',
    'poc.totalCount'
  ]

  const [kevCachedAt, enisaCachedAt, epssCachedEntry, pocCachedAt, metadata] = await Promise.all([
    loadCachedAt('kev-feed.json'),
    loadCachedAt('enisa-feed.json'),
    loadCachedAt('epss-feed.json'),
    loadCachedAt('github-poc-feed.json'),
    getMetadataMap(metadataKeys)
  ])

  const cvelistLastCommit = normaliseString(metadata['cvelist.lastCommit'])
  const cvelistLastRefreshAt = normaliseString(metadata['cvelist.lastRefreshAt'])
  const kevEntryCount = parseNumber(metadata['entryCount'] ?? metadata['catalog.entryCount'])
  const kevLastImportedAt = normaliseString(metadata['lastImportAt'])
  const kevNewCount = parseNumber(metadata['kev.lastNewCount']) ?? 0
  const kevUpdatedCount = parseNumber(metadata['kev.lastUpdatedCount']) ?? 0
  const kevSkippedCount = parseNumber(metadata['kev.lastSkippedCount']) ?? 0
  const kevRemovedCount = parseNumber(metadata['kev.lastRemovedCount']) ?? 0
  const kevStrategyRaw = normaliseString(metadata['kev.lastImportStrategy'])
  const kevStrategy: 'full' | 'incremental' = kevStrategyRaw === 'incremental' ? 'incremental' : 'full'
  const marketLastImportedAt = normaliseString(metadata['market.lastImportAt'])
  const marketCachedAt = normaliseString(metadata['market.cachedAt'])
  const marketOfferCount = parseNumber(metadata['market.offerCount'])
  const marketProgramCount = parseNumber(metadata['market.programCount'])
  const marketLastCaptureAt = normaliseString(metadata['market.lastCaptureAt'])
  const epssLastImportedAt = normaliseString(metadata['epss.lastImportAt'])
  const epssCachedAtMeta = normaliseString(metadata['epss.cachedAt'])
  const epssCachedAt = epssCachedAtMeta ?? epssCachedEntry ?? null
  const epssTotalCount = parseNumber(metadata['epss.totalCount'])
  const epssScoreDate = normaliseString(metadata['epss.lastScoreDate'])
  const epssModelVersion = normaliseString(metadata['epss.lastModelVersion'])
  const epssNewCount = parseNumber(metadata['epss.lastNewCount']) ?? 0
  const epssUpdatedCount = parseNumber(metadata['epss.lastUpdatedCount']) ?? 0
  const epssSkippedCount = parseNumber(metadata['epss.lastSkippedCount']) ?? 0
  const epssRemovedCount = parseNumber(metadata['epss.lastRemovedCount']) ?? 0
  const epssStrategyRaw = normaliseString(metadata['epss.lastImportStrategy'])
  const epssStrategy: 'full' | 'incremental' = epssStrategyRaw === 'incremental' ? 'incremental' : 'full'

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
        catalogVersion: normaliseString(metadata['catalogVersion']),
        dateReleased: normaliseString(metadata['dateReleased']),
        lastImportedAt: kevLastImportedAt,
        cachedAt: kevCachedAt,
        totalCount: kevEntryCount,
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'enisa',
        label: 'ENISA exploited catalog',
        importKey: 'enisa',
        catalogVersion: normaliseString(metadata['enisa.lastUpdatedAt']),
        dateReleased: null,
        lastImportedAt: normaliseString(metadata['enisa.lastImportAt']),
        cachedAt: enisaCachedAt,
        totalCount: parseNumber(metadata['enisa.totalCount']),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'epss',
        label: 'EPSS scores',
        importKey: 'epss',
        catalogVersion: epssModelVersion,
        dateReleased: epssScoreDate,
        lastImportedAt: epssLastImportedAt,
        cachedAt: epssCachedAt,
        totalCount: epssTotalCount,
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'historic',
        label: 'Historic exploit dataset',
        importKey: 'historic',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: normaliseString(metadata['historic.lastImportAt']),
        cachedAt: null,
        totalCount: parseNumber(metadata['historic.totalCount']),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'custom',
        label: 'Curated research feed',
        importKey: 'custom',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: normaliseString(metadata['custom.lastImportAt']),
        cachedAt: null,
        totalCount: parseNumber(metadata['custom.totalCount']),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'metasploit',
        label: 'Metasploit',
        importKey: 'metasploit',
        catalogVersion: normaliseString(metadata['metasploit.lastCommit']),
        dateReleased: null,
        lastImportedAt: normaliseString(metadata['metasploit.lastImportAt']),
        cachedAt: null,
        totalCount: parseNumber(metadata['metasploit.totalCount']),
        programCount: null,
        latestCaptureAt: null
      },
      {
        key: 'poc',
        label: 'GitHub PoC feed',
        importKey: 'poc',
        catalogVersion: null,
        dateReleased: null,
        lastImportedAt: normaliseString(metadata['poc.lastImportAt']),
        cachedAt: pocCachedAt ?? normaliseString(metadata['poc.cachedAt']),
        totalCount: parseNumber(metadata['poc.totalCount']),
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
    ],
    kevSummary: kevLastImportedAt
      ? {
          lastImportedAt: kevLastImportedAt,
          newCount: kevNewCount,
          updatedCount: kevUpdatedCount,
          skippedCount: kevSkippedCount,
          removedCount: kevRemovedCount,
          strategy: kevStrategy
        }
      : null
  }
})
