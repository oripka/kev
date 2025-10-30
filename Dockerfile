# syntax=docker/dockerfile:1.6

FROM node:20-bookworm-slim AS base

ENV PNPM_HOME="/root/.local/share/pnpm"
ENV PATH="${PNPM_HOME}:${PATH}"
ENV NUXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
ENV CI=true

WORKDIR /app

RUN corepack enable

RUN apt-get update \
  && apt-get install --no-install-recommends -y git python3 make g++ sqlite3 \
  && rm -rf /var/lib/apt/lists/*

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages ./packages

RUN pnpm fetch

COPY . .

RUN pnpm install --frozen-lockfile --offline --prod \
  && apt-get purge -y --auto-remove python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

VOLUME ["/app/data"]

CMD ["pnpm", "run", "import:incremental-deploy"]
