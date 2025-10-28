# Nuxt Minimal Starter

Look at the [Nuxt documentation](https://nuxt.com/docs/getting-started/introduction) to learn more.

## Setup

Make sure to install dependencies:

```bash
# npm
npm install

# pnpm
pnpm install

# yarn
yarn install

# bun
bun install
```

## Development Server

Start the development server on `http://localhost:3000`:

```bash
# npm
npm run dev

# pnpm
pnpm dev

# yarn
yarn dev

# bun
bun run dev
```

## Production

Build the application for production:

```bash
# npm
npm run build

# pnpm
pnpm build

# yarn
yarn build

# bun
bun run build
```

Locally preview production build:

```bash
# npm
npm run preview

# pnpm
pnpm preview

# yarn
yarn preview

# bun
bun run preview
```

Check out the [deployment documentation](https://nuxt.com/docs/getting-started/deployment) for more information.

## Data caches

The import pipeline keeps shallow clones of third-party feeds in `data/cache`.

- `data/cache/cvelist` — sparse checkout of [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) containing CVE JSON records.
- `data/cache/metasploit` — sparse checkout of the Metasploit Framework repository.

The CVEList cache is refreshed automatically when running the KEV importer. The most recent commit hash is stored in the `metadata` table under `cvelist.lastCommit` for observability. Admin users can trigger a manual refresh by calling `POST /api/admin/refresh-cvelist`, which also records the refresh timestamp under `cvelist.lastRefreshAt`.

## Import configuration

Set `NUXT_DISABLE_GITHUB_POC_IMPORT=true` (or `DISABLE_GITHUB_POC_IMPORT=true`) in your environment to skip the GitHub PoC importer. This keeps the database lighter by omitting the large GitHub PoC feed while leaving the rest of the ingestion pipeline untouched.
