# NuxtHub Database Migration Plan

## Objective

Migrate the application from the local `better-sqlite3` database to NuxtHub's Cloudflare D1 database for both development and production environments while preserving all existing functionality.

## Tasks

### 2. Swap SQLite client for NuxtHub `hubDatabase`

- We added `server/utils/drizzle.ts` -> use this useDrizzle for querying
- Dont use gor querying anymore `server/utils/sqlite.ts` (and any modules importing it) to use the new client, ensuring all Drizzle queries run against D1.
- Validate that existing composables/services (`server/api/*.ts`, market utilities, etc.) still compile and function with the new client.
- i think d1 cant do .transaction. so fix all thse any maybe stuff needs to be async.

## Usage

Rewrtie usage to work with d1 helpers like this

Usage
Select
server/api/todos/index.get.ts

export default eventHandler(async () => {
  const todos = await useDrizzle().select().from(tables.todos).all()

  return todos
})
Insert
server/api/todos/index.post.ts

export default eventHandler(async (event) => {
  const { title } = await readBody(event)

  const todo = await useDrizzle().insert(tables.todos).values({
    title,
    createdAt: new Date()
  }).returning().get()

  return todo
})
Update
server/api/todos/[id].patch.ts

export default eventHandler(async (event) => {
  const { id } = getRouterParams(event)
  const { completed } = await readBody(event)

  const todo = await useDrizzle().update(tables.todos).set({
    completed
  }).where(eq(tables.todos.id, Number(id))).returning().get()

  return todo
})
Delete
server/api/todos/[id].delete.ts

export default eventHandler(async (event) => {
  const { id } = getRouterParams(event)

  const deletedTodo = await useDrizzle().delete(tables.todos).where(and(
    eq(tables.todos.id, Number(id))
  )).returning().get()

  if (!deletedTodo) {
    throw createError({
      statusCode: 404,
      message: 'Todo not found'
    })
  }
  return deletedTodo
})



### 3. Rework migrations for Cloudflare D1
- Remvoe existing migrations start from a cleanshcema be sure it is compatible with s1
- Remove `better-sqlite3`-specific pragmas/logic (WAL, busy timeout, file paths) and replace with any D1 equivalents or guard code for local fallback if required.

- i will do thi ,anualyl add commands to nuke the db and recreate from scrathUse `npx drizzle-kit generate` or `npx nuxthub database migrations create` to regenerate baseline migrations, verifying they run via `nuxthub database migrations list`.
- Add documentation or scripts to seed data through NuxtHub post-migration hooks if the old `scripts/export-to-d1.mjs` workflow is no longer needed.

### 4. Simplify tooling around the new database
- Audit `scripts/export-to-d1.mjs` and other CLI helpers; remove or refactor them to call NuxtHub APIs (or eliminate if redundant).
- Replace any test/dev fixtures that read `data/db.sqlite` with seed commands hitting the NuxtHub DB or mock layers.
- Clean up dependencies (`better-sqlite3`, `sqlite3`) from `package.json` once nothing requires them.

