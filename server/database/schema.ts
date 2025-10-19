import { sql } from 'drizzle-orm'
import {
  index,
  integer,
  primaryKey,
  real,
  sqliteTable,
  text
} from 'drizzle-orm/sqlite-core'

export const catalogEntries = sqliteTable(
  'catalog_entries',
  {
    cveId: text('cve_id').primaryKey(),
    entryId: text('entry_id').notNull(),
    sources: text('sources').notNull(),
    vendor: text('vendor').notNull(),
    vendorKey: text('vendor_key').notNull(),
    product: text('product').notNull(),
    productKey: text('product_key').notNull(),
    vulnerabilityName: text('vulnerability_name').notNull(),
    description: text('description').notNull(),
    requiredAction: text('required_action'),
    dateAdded: text('date_added'),
    dateAddedTs: integer('date_added_ts'),
    dateAddedYear: integer('date_added_year'),
    dueDate: text('due_date'),
    ransomwareUse: text('ransomware_use'),
    hasKnownRansomware: integer('has_known_ransomware').notNull().default(0),
    notes: text('notes').notNull(),
    cwes: text('cwes').notNull(),
    cvssScore: real('cvss_score'),
    cvssVector: text('cvss_vector'),
    cvssVersion: text('cvss_version'),
    cvssSeverity: text('cvss_severity'),
    epssScore: real('epss_score'),
    assigner: text('assigner'),
    datePublished: text('date_published'),
    dateUpdated: text('date_updated'),
    dateUpdatedTs: integer('date_updated_ts'),
    exploitedSince: text('exploited_since'),
    sourceUrl: text('source_url'),
    referenceLinks: text('reference_links').notNull(),
    aliases: text('aliases').notNull(),
    isWellKnown: integer('is_well_known').notNull().default(0),
    domainCategories: text('domain_categories').notNull(),
    exploitLayers: text('exploit_layers').notNull(),
    vulnerabilityCategories: text('vulnerability_categories').notNull(),
    internetExposed: integer('internet_exposed').notNull().default(0),
    hasSourceKev: integer('has_source_kev').notNull().default(0),
    hasSourceEnisa: integer('has_source_enisa').notNull().default(0)
  },
  table => ({
    vendorKeyIdx: index('idx_catalog_entries_vendor_key').on(table.vendorKey),
    productKeyIdx: index('idx_catalog_entries_product_key').on(table.productKey),
    addedIdx: index('idx_catalog_entries_date_added_ts').on(table.dateAddedTs),
    updatedIdx: index('idx_catalog_entries_date_updated_ts').on(table.dateUpdatedTs),
    cvssIdx: index('idx_catalog_entries_cvss_score').on(table.cvssScore),
    epssIdx: index('idx_catalog_entries_epss_score').on(table.epssScore),
    wellKnownIdx: index('idx_catalog_entries_is_well_known').on(table.isWellKnown),
    ransomwareIdx: index('idx_catalog_entries_has_known_ransomware').on(table.hasKnownRansomware),
    internetExposedIdx: index('idx_catalog_entries_internet_exposed').on(table.internetExposed)
  })
)

export const catalogEntryDimensions = sqliteTable(
  'catalog_entry_dimensions',
  {
    cveId: text('cve_id').notNull(),
    dimension: text('dimension').notNull(),
    value: text('value').notNull(),
    name: text('name').notNull()
  },
  table => ({
    pk: primaryKey({ columns: [table.cveId, table.dimension, table.value] }),
    dimensionValueIdx: index('idx_catalog_entry_dimensions_dimension_value').on(
      table.dimension,
      table.value
    )
  })
)

export const vulnerabilityEntries = sqliteTable('vulnerability_entries', {
  id: text('id').primaryKey(),
  cveId: text('cve_id'),
  source: text('source').notNull(),
  vendor: text('vendor'),
  product: text('product'),
  vulnerabilityName: text('vulnerability_name'),
  description: text('description'),
  requiredAction: text('required_action'),
  dateAdded: text('date_added'),
  dueDate: text('due_date'),
  ransomwareUse: text('ransomware_use'),
  notes: text('notes'),
  cwes: text('cwes'),
  cvssScore: real('cvss_score'),
  cvssVector: text('cvss_vector'),
  cvssVersion: text('cvss_version'),
  cvssSeverity: text('cvss_severity'),
  epssScore: real('epss_score'),
  assigner: text('assigner'),
  datePublished: text('date_published'),
  dateUpdated: text('date_updated'),
  exploitedSince: text('exploited_since'),
  sourceUrl: text('source_url'),
  referenceLinks: text('reference_links'),
  aliases: text('aliases'),
  internetExposed: integer('internet_exposed').notNull().default(0),
  updatedAt: text('updated_at').default(sql`CURRENT_TIMESTAMP`)
})

export const vulnerabilityEntryCategories = sqliteTable(
  'vulnerability_entry_categories',
  {
    entryId: text('entry_id')
      .notNull()
      .references(() => vulnerabilityEntries.id, { onDelete: 'cascade' }),
    categoryType: text('category_type').notNull(),
    value: text('value').notNull(),
    name: text('name').notNull()
  },
  table => ({
    pk: primaryKey({ columns: [table.entryId, table.categoryType, table.value] }),
    typeValueIdx: index('idx_vulnerability_entry_categories_type_value').on(
      table.categoryType,
      table.value
    ),
    entryIdx: index('idx_vulnerability_entry_categories_entry').on(table.entryId)
  })
)

export const kevMetadata = sqliteTable('kev_metadata', {
  key: text('key').primaryKey(),
  value: text('value').notNull()
})

export const productCatalog = sqliteTable(
  'product_catalog',
  {
    productKey: text('product_key').primaryKey(),
    productName: text('product_name').notNull(),
    vendorKey: text('vendor_key').notNull(),
    vendorName: text('vendor_name').notNull(),
    sources: text('sources').notNull(),
    searchTerms: text('search_terms').notNull()
  },
  table => ({
    searchIdx: index('idx_product_catalog_search').on(table.searchTerms)
  })
)

export const userSessions = sqliteTable('user_sessions', {
  id: text('id').primaryKey(),
  createdAt: text('created_at').default(sql`CURRENT_TIMESTAMP`)
})

export const userProductFilters = sqliteTable(
  'user_product_filters',
  {
    sessionId: text('session_id')
      .notNull()
      .references(() => userSessions.id, { onDelete: 'cascade' }),
    vendorKey: text('vendor_key').notNull(),
    vendorName: text('vendor_name').notNull(),
    productKey: text('product_key').notNull(),
    productName: text('product_name').notNull(),
    createdAt: text('created_at').default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text('updated_at').default(sql`CURRENT_TIMESTAMP`)
  },
  table => ({
    pk: primaryKey({ columns: [table.sessionId, table.productKey] })
  })
)
