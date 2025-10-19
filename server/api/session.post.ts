import { randomUUID } from 'node:crypto'
import { tables } from '../database/client'
import { getDatabase } from '../utils/sqlite'

export default defineEventHandler(() => {
  const db = getDatabase()
  const sessionId = randomUUID()

  db.insert(tables.userSessions).values({ id: sessionId }).run()

  return {
    sessionId
  }
})
