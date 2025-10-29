CREATE VIRTUAL TABLE `catalog_entries_fts` USING fts5 (
  `cve_id`,
  `vendor`,
  `product`,
  `vulnerability_name`,
  `description`,
  `aliases`
);
