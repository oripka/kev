import { getImportProgress } from '../../utils/import-progress'

export default defineEventHandler(event => {
  setHeader(event, 'Cache-Control', 'no-store')
  return getImportProgress()
})

