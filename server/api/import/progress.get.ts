import { getImportProgress } from '../../utils/import-progress'
import { requireAdminKey } from '../../utils/adminAuth'

export default defineEventHandler(event => {
  requireAdminKey(event)
  setHeader(event, 'Cache-Control', 'no-store')
  return getImportProgress()
})

