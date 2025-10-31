import { gunzipSync } from 'node:zlib'
import { eq, sql } from 'drizzle-orm'
import { ofetch } from 'ofetch'
import { tables } from '../database/client'
import type { DrizzleDatabase } from '../database/client'
import { getCachedData } from './cache'
import { getMetadataValue, setMetadataValue } from './metadata'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'
import type { ImportStrategy } from './import-types'

const SOURCE_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
const CACHE_KEY = 'epss-feed'
const ONE_DAY_MS = 86_400_000
const EPSILON = 0.0001

const clampScore = (value: number): number => {
  if (!Number.isFinite(value)) {
    return 0
  }

  if (value <= 0) {
    return 0
  }

  if (value >= 100) {
    return 100
  }

  return value
}

type ParsedMetadata = {
  modelVersion: string | null
  scoreDate: string | null
}

type ParsedRecord = {
  cveId: string
  score: number
  percentile: number | null
}

type ParseResult = {
  metadata: ParsedMetadata
  records: ParsedRecord[]
}

const parseMetadataComment = (line: string): ParsedMetadata => {
  const trimmed = line.replace(/^#+/, '').trim()
  if (!trimmed) {
    return { modelVersion: null, scoreDate: null }
  }

  const segments = trimmed.split(',')
  let modelVersion: string | null = null
  let scoreDate: string | null = null

  for (const segment of segments) {
    const [rawKey, rawValue] = segment.split(':', 2)
    const key = rawKey?.trim().toLowerCase()
    const value = rawValue?.trim() ?? null

    if (!key || !value) {
      continue
    }

    if (key === 'model_version') {
      modelVersion = value
      continue
    }

    if (key === 'score_date') {
      scoreDate = value
      continue
    }
  }

  return { modelVersion, scoreDate }
}

const parseCsvDataset = (csv: string): ParseResult => {
  const lines = csv.split(/\r?\n/)

  let metadata: ParsedMetadata = { modelVersion: null, scoreDate: null }
  let headerIndex = 0

  while (headerIndex < lines.length) {
    const line = lines[headerIndex]?.trim()
    if (!line) {
      headerIndex += 1
      continue
    }

    if (line.startsWith('#')) {
      metadata = parseMetadataComment(line)
      headerIndex += 1
      continue
    }

    break
  }

  const headerLine = lines[headerIndex]?.trim() ?? ''
  const header = headerLine.toLowerCase()
  if (!header.includes('cve')) {
    throw new Error('EPSS dataset missing expected header row')
  }

  const records: ParsedRecord[] = []

  for (let index = headerIndex + 1; index < lines.length; index += 1) {
    const rawLine = lines[index]
    if (!rawLine) {
      continue
    }

    const line = rawLine.trim()
    if (!line || line.startsWith('#')) {
      continue
    }

    const [rawCve, rawScore, rawPercentile] = line.split(',', 3)
    const cveId = rawCve?.trim().toUpperCase()
    if (!cveId) {
      continue
    }

    const parsedScore = Number.parseFloat(rawScore ?? '')
    if (!Number.isFinite(parsedScore)) {
      continue
    }

    const scorePercent = clampScore(parsedScore * 100)

    const percentile = (() => {
      if (!rawPercentile) {
        return null
      }
      const parsed = Number.parseFloat(rawPercentile)
      return Number.isFinite(parsed) ? parsed : null
    })()

    records.push({
      cveId,
      score: Number.parseFloat(scorePercent.toFixed(5)),
      percentile
    })
  }

  return { metadata, records }
}

type ExistingEntry = {
  id: string
  cveId: string
  epssScore: number | null
}

type ImportOptions = {
  forceRefresh?: boolean
  allowStale?: boolean
  strategy?: ImportStrategy
}

type ImportSummary = {
  imported: number
  totalCount: number
  newCount: number
  updatedCount: number
  skippedCount: number
  removedCount: number
  strategy: ImportStrategy
  datasetVersion: string | null
  scoreDate: string | null
}

const loadExistingEntries = async (db: DrizzleDatabase): Promise<Map<string, ExistingEntry[]>> => {
  const rows = await db.all<ExistingEntry>(
    sql`SELECT id, cve_id as cveId, epss_score as epssScore FROM ${tables.vulnerabilityEntries} WHERE cve_id IS NOT NULL`
  )

  const map = new Map<string, ExistingEntry[]>()
  for (const row of rows) {
    if (!row.cveId) {
      continue
    }

    const key = row.cveId.toUpperCase()
    const bucket = map.get(key)
    if (bucket) {
      bucket.push({ ...row, cveId: key })
    } else {
      map.set(key, [{ ...row, cveId: key }])
    }
  }

  return map
}

export const importEpssScores = async (
  db: DrizzleDatabase,
  options: ImportOptions = {}
): Promise<ImportSummary> => {
  const { forceRefresh = false, allowStale = false } = options
  const strategy = options.strategy ?? 'full'

  markTaskRunning('epss', 'Checking EPSS cache')

  try {
    setImportPhase('fetchingEpss', {
      message: 'Checking EPSS cache',
      completed: 0,
      total: 0
    })
    markTaskProgress('epss', 0, 0, 'Checking EPSS cache')

    const dataset = await getCachedData(
      CACHE_KEY,
      async () => {
        setImportPhase('fetchingEpss', {
          message: 'Downloading EPSS scores',
          completed: 0,
          total: 0
        })
        markTaskProgress('epss', 0, 0, 'Downloading EPSS scores')

        const response = await ofetch<ArrayBuffer>(SOURCE_URL, { responseType: 'arrayBuffer' })
        const buffer = Buffer.from(response)
        const decompressed = gunzipSync(buffer).toString('utf8')
        return decompressed
      },
      { ttlMs: ONE_DAY_MS, forceRefresh, allowStale }
    )

    markTaskProgress(
      'epss',
      0,
      0,
      dataset.cacheHit ? 'Using cached EPSS scores' : 'Downloaded EPSS scores'
    )

    const { metadata, records } = parseCsvDataset(dataset.data)

    if (!records.length) {
      throw new Error('EPSS dataset did not contain any records')
    }

    const datasetSignature = `${metadata.modelVersion ?? ''}|${metadata.scoreDate ?? ''}|${records.length}`

    if (strategy === 'incremental' && !forceRefresh) {
      const previousSignature = await getMetadataValue('epss.lastDatasetSignature')
      if (previousSignature && previousSignature === datasetSignature) {
        const importedAt = new Date().toISOString()
        await Promise.all([
          setMetadataValue('epss.lastImportAt', importedAt),
          setMetadataValue('epss.lastImportStrategy', 'incremental'),
          setMetadataValue('epss.lastDatasetSignature', datasetSignature),
          setMetadataValue('epss.totalCount', String(records.length)),
          setMetadataValue('epss.lastScoreDate', metadata.scoreDate ?? ''),
          setMetadataValue('epss.lastModelVersion', metadata.modelVersion ?? ''),
          setMetadataValue('epss.lastNewCount', '0'),
          setMetadataValue('epss.lastUpdatedCount', '0'),
          setMetadataValue('epss.lastSkippedCount', String(records.length)),
          setMetadataValue('epss.lastRemovedCount', '0')
        ])

        markTaskComplete('epss', 'EPSS scores already up to date (cache unchanged)')
        return {
          imported: 0,
          totalCount: records.length,
          newCount: 0,
          updatedCount: 0,
          skippedCount: records.length,
          removedCount: 0,
          strategy: 'incremental',
          datasetVersion: metadata.modelVersion ?? null,
          scoreDate: metadata.scoreDate ?? null
        }
      }
    }

    const existingMap = await loadExistingEntries(db)

    const scoreMap = new Map<string, number>()
    for (const record of records) {
      scoreMap.set(record.cveId, record.score)
    }

    const updates: Array<{ id: string; value: number | null }> = []
    let newCount = 0
    let updatedCount = 0
    let skippedCount = 0
    let removedCount = 0

    for (const [cveId, entries] of existingMap.entries()) {
      const targetScore = scoreMap.get(cveId) ?? null

      const currentScores = entries.map(entry => entry.epssScore)
      const allNull = currentScores.every(value => value === null)
      const anyValue = currentScores.find(value => value !== null) ?? null

      if (targetScore === null) {
        if (anyValue !== null) {
          removedCount += 1
          for (const entry of entries) {
            if (entry.epssScore !== null) {
              updates.push({ id: entry.id, value: null })
            }
          }
        } else {
          skippedCount += 1
        }
        continue
      }

      const differs = entries.some(entry => {
        if (entry.epssScore === null) {
          return true
        }
        return Math.abs(entry.epssScore - targetScore) > EPSILON
      })

      if (!differs) {
        skippedCount += 1
        continue
      }

      if (allNull) {
        newCount += 1
      } else {
        updatedCount += 1
      }

      for (const entry of entries) {
        updates.push({ id: entry.id, value: targetScore })
      }
    }

    const totalUpdates = updates.length
    const importedAt = new Date().toISOString()

    if (totalUpdates > 0) {
      setImportPhase('savingEpss', {
        message: 'Updating EPSS scores in local cache',
        completed: 0,
        total: totalUpdates
      })
      markTaskProgress('epss', 0, totalUpdates, 'Updating EPSS scores in local cache')

      const batchCapableDb = db as { batch?: (queries: unknown[]) => Promise<unknown> }
      if (typeof batchCapableDb.batch === 'function') {
        await batchCapableDb.batch(
          updates.map(update =>
            db
              .update(tables.vulnerabilityEntries)
              .set({
                epssScore: update.value,
                updatedAt: importedAt
              })
              .where(eq(tables.vulnerabilityEntries.id, update.id))
          )
        )
      } else {
        for (let index = 0; index < updates.length; index += 1) {
          const update = updates[index]
          await db
            .update(tables.vulnerabilityEntries)
            .set({ epssScore: update.value, updatedAt: importedAt })
            .where(eq(tables.vulnerabilityEntries.id, update.id))
            .run()

          if ((index + 1) % 50 === 0 || index + 1 === updates.length) {
            const message = `Updating EPSS scores (${index + 1} of ${updates.length})`
            setImportPhase('savingEpss', {
              message,
              completed: index + 1,
              total: updates.length
            })
            markTaskProgress('epss', index + 1, updates.length, message)
          }
        }
      }
    } else {
      markTaskProgress('epss', 0, 0, 'No EPSS score changes detected for tracked CVEs')
    }

    await Promise.all([
      setMetadataValue('epss.lastImportAt', importedAt),
      setMetadataValue('epss.lastImportStrategy', strategy),
      setMetadataValue('epss.lastDatasetSignature', datasetSignature),
      setMetadataValue('epss.totalCount', String(records.length)),
      setMetadataValue('epss.lastScoreDate', metadata.scoreDate ?? ''),
      setMetadataValue('epss.lastModelVersion', metadata.modelVersion ?? ''),
      setMetadataValue('epss.lastNewCount', String(newCount)),
      setMetadataValue('epss.lastUpdatedCount', String(updatedCount)),
      setMetadataValue('epss.lastSkippedCount', String(skippedCount)),
      setMetadataValue('epss.lastRemovedCount', String(removedCount)),
      dataset.cachedAt ? setMetadataValue('epss.cachedAt', dataset.cachedAt.toISOString()) : Promise.resolve()
    ])

    const summarySegments: string[] = []
    if (newCount > 0) {
      summarySegments.push(`${newCount.toLocaleString()} new`)
    }
    if (updatedCount > 0) {
      summarySegments.push(`${updatedCount.toLocaleString()} updated`)
    }
    if (removedCount > 0) {
      summarySegments.push(`${removedCount.toLocaleString()} removed`)
    }
    if (!summarySegments.length) {
      summarySegments.push(`${skippedCount.toLocaleString()} unchanged`)
    }

    const summaryLabel = summarySegments.join(', ')
    markTaskComplete('epss', `Processed EPSS scores for ${existingMap.size.toLocaleString()} tracked CVEs (${summaryLabel})`)

    return {
      imported: totalUpdates,
      totalCount: records.length,
      newCount,
      updatedCount,
      skippedCount,
      removedCount,
      strategy,
      datasetVersion: metadata.modelVersion ?? null,
      scoreDate: metadata.scoreDate ?? null
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error'
    markTaskError('epss', `Failed to import EPSS scores: ${reason}`)
    throw error
  }
}

