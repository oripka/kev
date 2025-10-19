CREATE TABLE `catalog_entries` (
	`cve_id` text PRIMARY KEY NOT NULL,
	`entry_id` text NOT NULL,
	`sources` text NOT NULL,
	`vendor` text NOT NULL,
	`vendor_key` text NOT NULL,
	`product` text NOT NULL,
	`product_key` text NOT NULL,
	`vulnerability_name` text NOT NULL,
	`description` text NOT NULL,
	`required_action` text,
	`date_added` text,
	`date_added_ts` integer,
	`date_added_year` integer,
	`due_date` text,
	`ransomware_use` text,
	`has_known_ransomware` integer DEFAULT 0 NOT NULL,
	`notes` text NOT NULL,
	`cwes` text NOT NULL,
	`cvss_score` real,
	`cvss_vector` text,
	`cvss_version` text,
	`cvss_severity` text,
	`epss_score` real,
	`assigner` text,
	`date_published` text,
	`date_updated` text,
	`date_updated_ts` integer,
	`exploited_since` text,
	`source_url` text,
	`reference_links` text NOT NULL,
	`aliases` text NOT NULL,
	`is_well_known` integer DEFAULT 0 NOT NULL,
	`domain_categories` text NOT NULL,
	`exploit_layers` text NOT NULL,
	`vulnerability_categories` text NOT NULL,
	`internet_exposed` integer DEFAULT 0 NOT NULL,
	`has_source_kev` integer DEFAULT 0 NOT NULL,
	`has_source_enisa` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_vendor_key` ON `catalog_entries` (`vendor_key`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_product_key` ON `catalog_entries` (`product_key`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_date_added_ts` ON `catalog_entries` (`date_added_ts`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_date_updated_ts` ON `catalog_entries` (`date_updated_ts`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_cvss_score` ON `catalog_entries` (`cvss_score`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_epss_score` ON `catalog_entries` (`epss_score`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_is_well_known` ON `catalog_entries` (`is_well_known`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_has_known_ransomware` ON `catalog_entries` (`has_known_ransomware`);--> statement-breakpoint
CREATE INDEX `idx_catalog_entries_internet_exposed` ON `catalog_entries` (`internet_exposed`);--> statement-breakpoint
CREATE TABLE `catalog_entry_dimensions` (
	`cve_id` text NOT NULL,
	`dimension` text NOT NULL,
	`value` text NOT NULL,
	`name` text NOT NULL,
	PRIMARY KEY(`cve_id`, `dimension`, `value`)
);
--> statement-breakpoint
CREATE INDEX `idx_catalog_entry_dimensions_dimension_value` ON `catalog_entry_dimensions` (`dimension`,`value`);--> statement-breakpoint
CREATE TABLE `kev_metadata` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `product_catalog` (
	`product_key` text PRIMARY KEY NOT NULL,
	`product_name` text NOT NULL,
	`vendor_key` text NOT NULL,
	`vendor_name` text NOT NULL,
	`sources` text NOT NULL,
	`search_terms` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_product_catalog_search` ON `product_catalog` (`search_terms`);--> statement-breakpoint
CREATE TABLE `user_product_filters` (
	`session_id` text NOT NULL,
	`vendor_key` text NOT NULL,
	`vendor_name` text NOT NULL,
	`product_key` text NOT NULL,
	`product_name` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(`session_id`, `product_key`),
	FOREIGN KEY (`session_id`) REFERENCES `user_sessions`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `user_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vulnerability_entries` (
	`id` text PRIMARY KEY NOT NULL,
	`cve_id` text,
	`source` text NOT NULL,
	`vendor` text,
	`product` text,
	`vulnerability_name` text,
	`description` text,
	`required_action` text,
	`date_added` text,
	`due_date` text,
	`ransomware_use` text,
	`notes` text,
	`cwes` text,
	`cvss_score` real,
	`cvss_vector` text,
	`cvss_version` text,
	`cvss_severity` text,
	`epss_score` real,
	`assigner` text,
	`date_published` text,
	`date_updated` text,
	`exploited_since` text,
	`source_url` text,
	`reference_links` text,
	`aliases` text,
	`internet_exposed` integer DEFAULT 0 NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `vulnerability_entry_categories` (
	`entry_id` text NOT NULL,
	`category_type` text NOT NULL,
	`value` text NOT NULL,
	`name` text NOT NULL,
	PRIMARY KEY(`entry_id`, `category_type`, `value`),
	FOREIGN KEY (`entry_id`) REFERENCES `vulnerability_entries`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_vulnerability_entry_categories_type_value` ON `vulnerability_entry_categories` (`category_type`,`value`);--> statement-breakpoint
CREATE INDEX `idx_vulnerability_entry_categories_entry` ON `vulnerability_entry_categories` (`entry_id`);