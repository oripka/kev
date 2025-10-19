import { defineEventHandler } from 'h3'
import { resetClassificationProgress } from '../../utils/classification-progress'
import { resetImportProgress } from '../../utils/import-progress'
import { resetDatabase } from '../../utils/sqlite'

export default defineEventHandler(() => {
  resetDatabase()
  resetImportProgress()
  resetClassificationProgress()

  return { reset: true }
})
