import { defineEventHandler } from 'h3'
import { resetClassificationProgress } from '../../utils/classification-progress'
import { resetImportProgress } from '../../utils/import-progress'
import { resetDatabase } from '../../utils/sqlite'
import { requireAdminKey } from '../../utils/adminAuth'

export default defineEventHandler(event => {
  requireAdminKey(event)
  resetDatabase()
  resetImportProgress()
  resetClassificationProgress()

  return { reset: true }
})
