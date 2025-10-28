import { randomUUID } from 'node:crypto'
import { tables, useDrizzle } from '../utils/drizzle'

export default defineEventHandler(async () => {
  const db = useDrizzle()
  const sessionId = randomUUID()

  await db.insert(tables.userSessions).values({ id: sessionId }).run()

  return {
    sessionId
  }
})
