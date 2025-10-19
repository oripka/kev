import { defineEventHandler } from 'h3'
import { rebuildCatalog } from '../../utils/catalog'
import { rebuildProductCatalog } from '../../utils/product-catalog'
import { getDatabase } from '../../utils/sqlite'
import {
  completeClassificationProgress,
  failClassificationProgress,
  setClassificationPhase,
  startClassificationProgress,
  updateClassificationProgress
} from '../../utils/classification-progress'

export default defineEventHandler(async () => {
  const db = getDatabase()

  startClassificationProgress('Preparing catalog reclassification…', 0)

  try {
    const summary = rebuildCatalog(db, {
      onStart(total) {
        setClassificationPhase('rebuilding', {
          total,
          completed: 0,
          message:
            total > 0
              ? `Reclassifying cached catalog (0 of ${total})`
              : 'Reclassifying cached catalog…'
        })
      },
      onProgress(completed, total) {
        const message =
          total > 0
            ? `Reclassifying cached catalog (${completed} of ${total})`
            : 'Reclassifying cached catalog…'
        updateClassificationProgress(completed, total, message)
      }
    })

    rebuildProductCatalog(db)

    const message = `Reclassified ${summary.count.toLocaleString()} catalog entries`
    completeClassificationProgress(`${message}.`)

    return {
      reclassified: summary.count,
      earliest: summary.earliest,
      latest: summary.latest
    }
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Unable to reclassify cached data'

    failClassificationProgress(message)
    throw error
  }
})
