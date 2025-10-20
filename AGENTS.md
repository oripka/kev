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

- [ ] make a helper to render the dates and render the conssitently in all the app make a configuration siwthc for european/american format ing. in general dont render the hours. make a switch for that but off by default
- [ ] rename kevmodal and other components that are not kev only anymore.
- [x] make all the badged from domain, exploit dynamics, vulnerbailtiy mix, date (just fitler for that year), cisa kev, , enisa , vendor, produ ct and so on clickable so it goes tothe catalog with that filter active, add to exisitng filters. have an otpion in the settings to have it clear the filtrers nad apply it a snew. but default to or .   
- [x] Add a dedicated poage for the vulns of the last two weeks. show as a list or cards in a grid 1 col or 2 cols. with a fancy card that has some detials about all the vulns.
- [ ] Add auth and persist my software to database per user
- [ ] Alerting (Slack / Email) when a new "in the wild" CVE matches saved filters.
- [ ] Make badge colors more consisten (enisa stands out from the source and has differnet color i the filter panel than int he vuln display