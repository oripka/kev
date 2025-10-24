import { defineEventHandler } from 'h3'
import { getClassificationProgress } from '../../../utils/classification-progress'
import { requireAdminKey } from '../../../utils/adminAuth'

export default defineEventHandler(event => {
  requireAdminKey(event)
  return getClassificationProgress()
})
