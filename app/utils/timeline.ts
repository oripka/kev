import { addDays, addMonths, addWeeks, startOfDay, startOfMonth, startOfWeek } from 'date-fns'
import type { KevEntrySummary, KevTimeline, KevTimelineBucket, Period } from '~/types'

const WEEK_OPTIONS = { weekStartsOn: 1 as const }

const aligners: Record<Period, (date: Date) => Date> = {
  daily: startOfDay,
  weekly: (date) => startOfWeek(date, WEEK_OPTIONS),
  monthly: startOfMonth,
}

const incrementers: Record<Period, (date: Date) => Date> = {
  daily: (date) => addDays(date, 1),
  weekly: (date) => addWeeks(date, 1),
  monthly: (date) => addMonths(date, 1),
}

const createEmptyTimeline = (): KevTimeline => ({
  range: null,
  buckets: {
    daily: [],
    weekly: [],
    monthly: [],
  },
})

const buildBuckets = (
  timestamps: number[],
  period: Period,
  start: Date,
  end: Date,
): KevTimelineBucket[] => {
  const align = aligners[period]
  const increment = incrementers[period]

  const alignedStart = align(new Date(start))
  const alignedEnd = align(new Date(end))

  const buckets: Array<{ time: number; count: number }> = []
  const endTime = alignedEnd.getTime()

  for (let cursor = alignedStart; cursor.getTime() <= endTime;) {
    const time = cursor.getTime()
    buckets.push({ time, count: 0 })
    cursor = increment(cursor)
  }

  if (!buckets.length) {
    return []
  }

  const indexByTime = new Map<number, number>()
  buckets.forEach((bucket, index) => {
    indexByTime.set(bucket.time, index)
  })

  for (const timestamp of timestamps) {
    const aligned = align(new Date(timestamp))
    const index = indexByTime.get(aligned.getTime())
    if (index === undefined) {
      continue
    }

    buckets[index].count += 1
  }

  return buckets.map((bucket) => ({
    date: new Date(bucket.time).toISOString(),
    count: bucket.count,
  }))
}

export const buildTimeline = (entries: readonly KevEntrySummary[]): KevTimeline => {
  const timestamps = entries
    .map((entry) => {
      const date = new Date(entry.dateAdded)
      const time = date.getTime()
      return Number.isNaN(time) ? null : time
    })
    .filter((value): value is number => value !== null)

  if (!timestamps.length) {
    return createEmptyTimeline()
  }

  timestamps.sort((a, b) => a - b)

  const start = new Date(timestamps[0])
  const end = new Date(timestamps[timestamps.length - 1])

  return {
    range: {
      start: start.toISOString(),
      end: end.toISOString(),
    },
    buckets: {
      daily: buildBuckets(timestamps, 'daily', start, end),
      weekly: buildBuckets(timestamps, 'weekly', start, end),
      monthly: buildBuckets(timestamps, 'monthly', start, end),
    },
  }
}
