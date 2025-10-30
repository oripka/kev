# syntax=docker/dockerfile:1.6

FROM node:20-bookworm-slim AS base

ENV PNPM_HOME="/root/.local/share/pnpm"
ENV PATH="${PNPM_HOME}:${PATH}"
ENV NUXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
ENV CI=true

WORKDIR /app
RUN corepack enable

FROM base AS deps

RUN apt-get update \
  && apt-get install --no-install-recommends -y git python3 make g++ sqlite3 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY .npmrc ./
RUN mkdir -p packages/feed-importer
COPY packages/feed-importer/package.json packages/feed-importer/package.json

RUN pnpm fetch --prod \
  && pnpm install --frozen-lockfile --prod

FROM base AS runner

RUN apt-get update \
  && apt-get install --no-install-recommends -y git sqlite3 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=deps /root/.local/share/pnpm /root/.local/share/pnpm
COPY --from=deps /app/node_modules /app/node_modules
COPY --from=deps /app/package.json /app/package.json
COPY --from=deps /app/pnpm-lock.yaml /app/pnpm-lock.yaml
COPY --from=deps /app/pnpm-workspace.yaml /app/pnpm-workspace.yaml
COPY --from=deps /app/.npmrc /app/.npmrc

COPY . .

VOLUME ["/app/data"]

CMD ["pnpm", "run", "import:incremental-deploy"]
