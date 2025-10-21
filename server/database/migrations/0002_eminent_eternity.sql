CREATE TABLE `market_offer_categories` (
	`offer_id` text NOT NULL,
	`category_type` text NOT NULL,
	`category_key` text NOT NULL,
	`category_name` text NOT NULL,
	PRIMARY KEY(`offer_id`, `category_type`, `category_key`),
	FOREIGN KEY (`offer_id`) REFERENCES `market_offers`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_market_offer_categories_type` ON `market_offer_categories` (`category_type`,`category_key`);--> statement-breakpoint
CREATE TABLE `market_offer_metrics` (
	`id` text PRIMARY KEY NOT NULL,
	`offer_id` text NOT NULL,
	`valuation_score` real NOT NULL,
	`score_breakdown` text NOT NULL,
	`computed_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`offer_id`) REFERENCES `market_offers`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_market_offer_metrics_offer` ON `market_offer_metrics` (`offer_id`);--> statement-breakpoint
CREATE INDEX `idx_market_offer_metrics_computed` ON `market_offer_metrics` (`computed_at`);--> statement-breakpoint
CREATE TABLE `market_offer_targets` (
	`offer_id` text NOT NULL,
	`product_key` text NOT NULL,
	`cve_id` text,
	`confidence` integer DEFAULT 100 NOT NULL,
	`match_method` text DEFAULT 'exact' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(`offer_id`, `product_key`),
	FOREIGN KEY (`offer_id`) REFERENCES `market_offers`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`product_key`) REFERENCES `product_catalog`(`product_key`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_market_offer_targets_product` ON `market_offer_targets` (`product_key`);--> statement-breakpoint
CREATE INDEX `idx_market_offer_targets_cve` ON `market_offer_targets` (`cve_id`);--> statement-breakpoint
CREATE TABLE `market_offers` (
	`id` text PRIMARY KEY NOT NULL,
	`program_id` text NOT NULL,
	`cve_id` text,
	`title` text NOT NULL,
	`description` text,
	`min_reward_usd` real,
	`max_reward_usd` real,
	`currency` text DEFAULT 'USD' NOT NULL,
	`reward_type` text DEFAULT 'range' NOT NULL,
	`exclusivity` text,
	`source_url` text NOT NULL,
	`source_capture_date` text NOT NULL,
	`effective_start` text,
	`effective_end` text,
	`terms_hash` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`program_id`) REFERENCES `market_programs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_market_offers_program` ON `market_offers` (`program_id`);--> statement-breakpoint
CREATE INDEX `idx_market_offers_capture` ON `market_offers` (`source_capture_date`);--> statement-breakpoint
CREATE TABLE `market_program_snapshots` (
	`id` text PRIMARY KEY NOT NULL,
	`program_id` text NOT NULL,
	`fetched_at` text NOT NULL,
	`raw_content` text NOT NULL,
	`parser_version` text NOT NULL,
	`content_hash` text,
	FOREIGN KEY (`program_id`) REFERENCES `market_programs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_market_program_snapshots_program` ON `market_program_snapshots` (`program_id`);--> statement-breakpoint
CREATE INDEX `idx_market_program_snapshots_fetched` ON `market_program_snapshots` (`fetched_at`);--> statement-breakpoint
CREATE TABLE `market_programs` (
	`id` text PRIMARY KEY NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`operator` text NOT NULL,
	`program_type` text NOT NULL,
	`homepage_url` text NOT NULL,
	`scrape_frequency` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	`description` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_market_programs_slug` ON `market_programs` (`slug`);--> statement-breakpoint
CREATE INDEX `idx_market_programs_type` ON `market_programs` (`program_type`);