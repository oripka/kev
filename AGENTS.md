# In the Wild

A simple dashboard and analytics tool for CISA’s Known Exploited Vulnerabilities (KEV) list, Ensia exploited list and custom historci lists.

- dont start a dev server , run builds or run tests just write the code

1. Purpose

A lightweight tool for companies and researchers to view, filter, and analyze the CISA KEV catalog.
The app highlights which products, vendors, and categories are most exploited in the wild and gives actionable, data-driven insights.


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

11. Roadmap (Later Features)
	•	Slack / Email alert when a new KEV matches filters
	•	Tag “affected products” by importing internal inventory
	•	Add “exploit references” and “remediation links”
	•	Role-based access, team sharing
	•	Dark mode, mobile-friendly charts

