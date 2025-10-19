import { defineEventHandler } from 'h3'
import { getClassificationProgress } from '../../../utils/classification-progress'

export default defineEventHandler(() => {
  return getClassificationProgress()
})
