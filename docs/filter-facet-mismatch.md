# Filter facet stats ignore active filters

## Summary

The counts displayed in the Catalog filter sidebar (e.g. "Exploit dynamics")
were inconsistent with the table results. When a user selected a filter such as
`vendor=microsoft`, the table correctly returned no matching entries, but the
facet still reported several matching vulnerabilities. This happened because the
count queries intentionally dropped vendor and product filters, so the facet
aggregates were calculated across the entire dataset instead of the active
filter set.

## Impact

- Facet counts suggested vulnerabilities existed for the selected filter set
  even when the table was empty.
- Users could not rely on the sidebar metrics to understand what matched their
  query.

## Root cause

`kev/server/api/kev.get.ts` builds each facet by calling `queryDimensionCounts`
with a filtered query. The helper `omitFilters` removes filters that should be
ignored for a particular facet. The exploit, domain, vulnerability and vendor
facets were using a broad omit list that removed vendor and product filters
altogether. As a result, the counts were computed without those constraints and
showed totals for the entire catalog.

## Fix

- Only drop the filter for the facet being evaluated (e.g. remove `exploit`
  when computing exploit counts, but keep vendor/product filters).
- Preserve product filters when computing vendor counts.

This ensures every facet reflects the currently active filter set so the table
and sidebar stay in sync.
