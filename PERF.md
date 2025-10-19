## Refactor index.vue

## Optmize

-Database Schema
- [ ] You can drop all existing data and reinitialize the tables. No need for database migrations at this stage — just add a button to perform the reset. Keep the schema clean and free of legacy code.
- [ ] Avoid storing categorical data such as exploit categories, domain categories, or vulnerability categories as plain strings.
- [ ] This severely impacts query performance. Normalize the database structure for better performance, consistency, and easier imports/queries.
- [ ]  merge the kev_entries and enisa_entries tables into a single table with a source field ('KEV' or 'ENISA').
- [ ] This avoids duplication and makes querying simpler.
- [ ] Avoid using reserved SQL keywords (e.g., references) as column names to prevent conflicts with SQLite.
- [ ] on intiial index.vue load dont load all vulnerabilties but jsut the last 25 in the list. but make sure that the staitics and the Category insights are still showing the correctoverall numebrs not just of the show vulns, same for Vendor & product leader. this should be failry easy when we have all data inthe datbase. 
- [ ] fix any other bugs

## Optmize

if you did the above this should be easy:

- [ ] Optimize queries such as:
http://localhost:3001/api/kev?domain=Non-Web+Applications&startYear=2021&endYear=2025
These currently fetch too much data from the database. For the listing view, we only need the fields shown in the table. Load detailed information only when the user opens the modal for a specific vulnerability.
	•	On initial load or when filters are applied, fetch only the data required for the table display.
	•	Add a “Reclassify Cached Data” button to the admin dashboard.
Show the classification progress in real time.
