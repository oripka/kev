# In the Wild

A lightweight dashboard and analytics tool for tracking actively exploited vulnerabilities across multiple feeds (CISA KEV, ENSISA and custom historical lists).

> Note: this repository contains code only. Do **not** start a dev server, run builds, or run tests — just write and review the code.


## Purpose

Provide companies and researchers with a compact, practical interface to view, filter, and analyze exploited-vulnerability feeds. The app highlights which vendors, products, and categories are most targeted in the wild and provides actionable, data-driven insights.

## Tech stack

| Layer     | Technology                                  |
|-----------|---------------------------------------------|
| Frontend  | Nuxt 4 + Nuxt UI v4 (see docs/nuxtui/)      |
| Styling   | TailwindCSS (via Nuxt UI)                   |
| Backend   | Supabase (Postgres + REST)                  |
| Data      | CISA KEV JSON/CSV, ENSISA, custom feeds     |
| Deployment| Static Nuxt site (with server routes)       |

See `NUXTUI.md` for Nuxt UI details.

## Core features

- **Import & update feeds** — fetch and store the latest CISA KEV, ENSISA, and custom lists.
- **Browse & filter** — search by CVE ID, vendor, product, category, vulnerability type, date added, or severity.
- **Statistics** — charts for top vendors, product categories, vulnerability families, and exploit frequency.
- **Trends** — visualize how exploited vulnerabilities evolve over time.
- **Export** — CSV download for filtered results.
- **Data provenance** — reference original feed entries and links to sources.


## Implementation

- Use Drizzle/Sqlite for storage.
- Normalize vendor/product names at import to improve grouping and statistics.
- Keep data schema minimal and audit-friendly (CVE, vendor, product, versions, feed source, date added, references, severity).
- Provide a server route to pull fresh feeds and an import job that upserts records.
- Do **not** include internal inventory integrations in the initial release — leave as an opt-in feature.


## Roadmap

- [ ] Add auth and persist my software to database per user
- [ ] Alerting (Slack / Email) when a new "in the wild" CVE matches saved filters.

