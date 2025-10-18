KEV Watch — a simple dashboard and analytics tool for CISA’s Known Exploited Vulnerabilities (KEV) list.

- dont start a dev server , run builds or run tests just write the code
⸻

1. Purpose

A lightweight tool for companies and researchers to view, filter, and analyze the CISA KEV catalog.
The app highlights which products, vendors, and categories are most exploited in the wild and gives actionable, data-driven insights.

⸻

2. Tech Stack

Layer	Technology
Frontend	Nuxt 4 + Nuxt UI v4 https://ui.nuxt.com see NUXTUI.md for details
Styling	TailwindCSS (included via Nuxt UI)
Backend	Supabase (Postgres + REST)
Data Source	Official CISA KEV JSON/CSV feed
Deployment	Static Nuxt site with a server route for fetching KEV data

USE Nuxt ui 3/4 there is nuxtui-llms-full.txt (just look at chucks or grep because it is huge) for reference 

⸻

3. Features
	•	Import & Update KEV List: Fetch and store the latest CISA KEV data.
	•	Browse & Filter: Search by CVE ID, vendor, product, product category, vulnerability type, date added, or severity.
	•	Statistics: Show charts for top vendors, product categories, and vulnerability types.
	•	Trends: Track how the number of exploited vulnerabilities evolves over time.
	•	Export: CSV download of filtered results.
	•	(Optional later): Alert subscriptions or saved filters.

⸻

4. Data Model (Supabase Schema)

create table kev_entries (
  id uuid primary key default gen_random_uuid(),
  cve_id text unique not null,
  vendor text,
  product text,
  category text,
  vulnerability_type text,
  date_added date,
  required_action text,
  short_description text,
  cvss_score numeric,
  epss_score numeric,
  exploit_maturity text,
  known_ransomware boolean default false,
  source_url text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);


⸻

5. Data Flow
	1.	Fetch KEV Data
	•	A Nuxt server route (e.g. /server/api/fetchKev.ts) fetches JSON from
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json.
	•	Parse and upsert into kev_entries (via Supabase client).
	2.	Frontend Display
	•	/pages/index.vue → Overview dashboard.
	•	/pages/list.vue → Full KEV table with filters.
	•	/pages/stats.vue → Charts and summaries.
	3.	Filtering & Sorting
	•	Client-side filtering using composables.
	•	Optional server-side queries with Supabase filters for scalability.

⸻

6. Example Queries

Fetch all entries:

const { data } = await supabase.from('kev_entries').select('*').order('date_added', { ascending: false })

Filter by vendor:

const { data } = await supabase
  .from('kev_entries')
  .select('*')
  .ilike('vendor', '%Cisco%')

Get top vendors (for chart):

select vendor, count(*) as count
from kev_entries
group by vendor
order by count desc
limit 10;


⸻

7. Pages / Components Structure

/app
  /pages
    index.vue        → Summary cards + top stats
    list.vue         → Data table with filters (Nuxt UI Table + SearchInput)
    stats.vue        → Charts (bar, line)
  /components
    KevTable.vue
    FilterPanel.vue
    StatCard.vue
    VendorChart.vue
    CategoryChart.vue
  /server/api
    fetchKev.ts      → Imports latest CISA KEV feed


⸻

8. UI Ideas (Nuxt UI v4 Components)
	•	UCard → for each statistic or summary.
	•	UTable → main vulnerabilities table.
	•	UInput, USelect, UCheckbox → for filtering panel.
	•	UBadge → severity / exploit maturity indicators.
	•	UChart (or Chart.js wrapper) → for vendor/category trend charts.
	•	UButton → refresh or export buttons.
	•	USkeleton → loading states.

⸻

9. Example Dashboard Metrics
	•	Total KEV entries
	•	New KEVs this week
	•	Most targeted vendors
	•	Top exploited categories
	•	Avg CVSS / EPSS
	•	Count of ransomware-linked vulnerabilities

⸻

10. Example UI Flow
	1.	Landing / Dashboard:
Shows key stats and last update timestamp.
	2.	KEV Table View:
Filterable, sortable table of vulnerabilities with key columns:
CVE ID | Vendor | Product | CVSS | Exploit Maturity | Added | Description.
	3.	Stats Page:
Bar chart: “Top 10 Vendors by Exploited Vulnerabilities”
Pie chart: “Distribution by Product Category”
Line chart: “KEV Growth Over Time”.
	4.	Manual Update Button:
Calls /api/fetchKev → updates Supabase → refresh page.

⸻

11. Roadmap (Later Features)
	•	Slack / Email alert when a new KEV matches filters
	•	Tag “affected products” by importing internal inventory
	•	Add “exploit references” and “remediation links”
	•	Role-based access, team sharing
	•	Dark mode, mobile-friendly charts

⸻

This version keeps everything minimal and self-contained —
just Nuxt UI, Supabase DB, and a scheduled or manual fetch route.
