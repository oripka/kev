# NuxtHub Database Migration Plan

## Objective

Migrate the application from the local `better-sqlite3` database to NuxtHub's Cloudflare D1 database for both development and production environments while preserving all existing functionality.

## Tasks

### 2. Swap SQLite client for NuxtHub `hubDatabase`

- Inventory every import of `server/utils/sqlite.ts` (or any helper that returns the `better-sqlite3` client) across `server/api`, composables, and utility layers using `rg "server/utils/sqlite"`; record each file that needs refactoring.
- For each identified module:
  - Replace the sqlite import with `useDrizzle` from `server/utils/drizzle.ts`.
  - Rewrite synchronous `db.prepare()/all()/get()` calls into async Drizzle query builder calls (`await useDrizzle().select(...)`, etc.), returning promises instead of synchronous values.
  - Adjust call sites that expected synchronous data to `await` the new async functions or propagate the promise upward.
- Remove any remaining helpers or exports in `server/utils/sqlite.ts`; if other modules re-exported it, update them to use the Drizzle helper and delete the unused sqlite file once the tree is clear.
- Review every `.transaction(…)` usage and refactor:
  - Prefer explicit sequential `await` calls, batching writes with Drizzle’s `insert`/`update` helpers where possible.
  - If true transactional guarantees are required, document the limitation and gate the code path behind a fallback or retry loop compatible with D1.
- Re-run TypeScript checks (`pnpm typecheck`) to confirm composables, server routes, and market utilities compile with the async Drizzle client.
- Manually spot-check a few representative API handlers (read, write, filter-heavy endpoints) to ensure query results still match expectations with the D1-backed driver.

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
