import { defineEventHandler } from 'h3'
import { requireAdminKey } from '../../utils/adminAuth'
import { syncCvelistRepo } from '../../utils/cvelist'
import { setMetadataValue } from '../../utils/metadata'

export default defineEventHandler(async event => {
  requireAdminKey(event)

  const result = await syncCvelistRepo()
  const refreshedAt = new Date().toISOString()
  await setMetadataValue('cvelist.lastRefreshAt', refreshedAt)

  return {
    refreshed: true,
    updated: result.updated,
    commit: result.commit,
    refreshedAt
  }
})
