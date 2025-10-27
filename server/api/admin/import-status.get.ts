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

type SourceImportSummary = {
  lastImportedAt: string | null
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: 'full' | 'incremental'
}

type ImportStatusResponse = {
  sources: ImportSourceStatus[]
  kevSummary: SourceImportSummary | null
  sourceSummaries: Partial<Record<ImportTaskKey, SourceImportSummary>>
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

const parseStrategy = (value: string | null): 'full' | 'incremental' => {
  return normaliseString(value) === 'incremental' ? 'incremental' : 'full'
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
  const kevLastImportedAt = normaliseString(getMetadata('lastImportAt'))
  const kevNewCount = parseNumber(getMetadata('kev.lastNewCount')) ?? 0
  const kevUpdatedCount = parseNumber(getMetadata('kev.lastUpdatedCount')) ?? 0
  const kevSkippedCount = parseNumber(getMetadata('kev.lastSkippedCount')) ?? 0
  const kevRemovedCount = parseNumber(getMetadata('kev.lastRemovedCount')) ?? 0
  const kevStrategyRaw = normaliseString(getMetadata('kev.lastImportStrategy'))
  const kevStrategy: 'full' | 'incremental' = kevStrategyRaw === 'incremental' ? 'incremental' : 'full'
  const historicLastImportedAt = normaliseString(getMetadata('historic.lastImportAt'))
  const historicNewCount = parseNumber(getMetadata('historic.lastNewCount')) ?? 0
  const historicUpdatedCount = parseNumber(getMetadata('historic.lastUpdatedCount')) ?? 0
  const historicSkippedCount = parseNumber(getMetadata('historic.lastSkippedCount')) ?? 0
  const historicRemovedCount = parseNumber(getMetadata('historic.lastRemovedCount')) ?? 0
  const historicStrategy = parseStrategy(getMetadata('historic.lastImportStrategy'))
  const enisaLastImportAt = normaliseString(getMetadata('enisa.lastImportAt'))
  const enisaNewCount = parseNumber(getMetadata('enisa.lastNewCount')) ?? 0
  const enisaUpdatedCount = parseNumber(getMetadata('enisa.lastUpdatedCount')) ?? 0
  const enisaSkippedCount = parseNumber(getMetadata('enisa.lastSkippedCount')) ?? 0
  const enisaRemovedCount = parseNumber(getMetadata('enisa.lastRemovedCount')) ?? 0
  const enisaStrategy = parseStrategy(getMetadata('enisa.lastImportStrategy'))
  const metasploitLastImportAt = normaliseString(getMetadata('metasploit.lastImportAt'))
  const metasploitNewCount = parseNumber(getMetadata('metasploit.lastNewCount')) ?? 0
  const metasploitUpdatedCount = parseNumber(getMetadata('metasploit.lastUpdatedCount')) ?? 0
  const metasploitSkippedCount = parseNumber(getMetadata('metasploit.lastSkippedCount')) ?? 0
  const metasploitRemovedCount = parseNumber(getMetadata('metasploit.lastRemovedCount')) ?? 0
  const metasploitStrategy = parseStrategy(getMetadata('metasploit.lastImportStrategy'))
  const pocLastImportAt = normaliseString(getMetadata('poc.lastImportAt'))
  const pocNewCount = parseNumber(getMetadata('poc.lastNewCount')) ?? 0
  const pocUpdatedCount = parseNumber(getMetadata('poc.lastUpdatedCount')) ?? 0
  const pocSkippedCount = parseNumber(getMetadata('poc.lastSkippedCount')) ?? 0
  const pocRemovedCount = parseNumber(getMetadata('poc.lastRemovedCount')) ?? 0
  const pocStrategy = parseStrategy(getMetadata('poc.lastImportStrategy'))
  const marketLastImportedAt = normaliseString(getMetadata('market.lastImportAt'))
  const marketCachedAt = normaliseString(getMetadata('market.cachedAt'))
  const marketOfferCount = parseNumber(getMetadata('market.offerCount'))
  const marketProgramCount = parseNumber(getMetadata('market.programCount'))
  const marketLastCaptureAt = normaliseString(getMetadata('market.lastCaptureAt'))

  const sourceSummaries: Partial<Record<ImportTaskKey, SourceImportSummary>> = {}

  const kevSummary = kevLastImportedAt
    ? {
        lastImportedAt: kevLastImportedAt,
        newCount: kevNewCount,
        updatedCount: kevUpdatedCount,
        skippedCount: kevSkippedCount,
        removedCount: kevRemovedCount,
        strategy: kevStrategy
      }
    : null

  if (kevSummary) {
    sourceSummaries.kev = kevSummary
  }

  if (historicLastImportedAt) {
    sourceSummaries.historic = {
      lastImportedAt: historicLastImportedAt,
      newCount: historicNewCount,
      updatedCount: historicUpdatedCount,
      skippedCount: historicSkippedCount,
      removedCount: historicRemovedCount,
      strategy: historicStrategy
    }
  }

  if (enisaLastImportAt) {
    sourceSummaries.enisa = {
      lastImportedAt: enisaLastImportAt,
      newCount: enisaNewCount,
      updatedCount: enisaUpdatedCount,
      skippedCount: enisaSkippedCount,
      removedCount: enisaRemovedCount,
      strategy: enisaStrategy
    }
  }

  if (metasploitLastImportAt) {
    sourceSummaries.metasploit = {
      lastImportedAt: metasploitLastImportAt,
      newCount: metasploitNewCount,
      updatedCount: metasploitUpdatedCount,
      skippedCount: metasploitSkippedCount,
      removedCount: metasploitRemovedCount,
      strategy: metasploitStrategy
    }
  }

  if (pocLastImportAt) {
    sourceSummaries.poc = {
      lastImportedAt: pocLastImportAt,
      newCount: pocNewCount,
      updatedCount: pocUpdatedCount,
      skippedCount: pocSkippedCount,
      removedCount: pocRemovedCount,
      strategy: pocStrategy
    }
  }

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
        catalogVersion: normaliseString(getMetadata('enisa.lastUpdatedAt')),
        dateReleased: null,
        lastImportedAt: enisaLastImportAt,
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
        lastImportedAt: historicLastImportedAt,
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
        lastImportedAt: metasploitLastImportAt,
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
        lastImportedAt: pocLastImportAt,
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
    ],
    kevSummary,
    sourceSummaries
  }
})
