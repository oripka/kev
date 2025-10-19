import { randomUUID } from 'node:crypto'
import { getDatabase } from '../utils/sqlite'

export default defineEventHandler(() => {
  const db = getDatabase()
  const sessionId = randomUUID()

  db.prepare('INSERT INTO user_sessions (id) VALUES (?)').run(sessionId)

  return {
    sessionId
  }
})
