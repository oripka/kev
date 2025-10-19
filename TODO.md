# TODO

some of these might already be implmented if yes just check - [x] them . if not fix it 


- [x] Add a ransomware spotlight filter state, active filter chips, and UI controls so users can focus the dashboard on ransomware-linked CVEs.
- [x] Ensure the query payload includes the new parameter.
- [x] Add an option to show trend lines for the filtered vulnerabilities (to visualize frequency over time, use Univis).
- [x] Implement this trend-line option as a toggle switch in the UI.

- [x] Create a category / edge for items typically exposed on the open internet (e.g. SSL VPN, Citrix ADC, Exchange, web apps, etc.).
- [x] Identify and define reliable indicators to make this category accurate and consistent.

- [x] Move the diagram into its own component.
- [x] Refactor and decompose where it makes sense to improve structure and maintainability.

- [x] Fix the “Add to my software” function — currently not working.
- [x] Improve dropdown performance (currently very slow).
- [x] Store imported software data in a database table during import (from KEV and ENISA).
- [x] Create a separate configuration page for this and link it in the header.

- [x] Fix the “Add to product list” button — currently does nothing even after selecting a product.
- [x] Ensure it updates the number of selected products.
- [x] Save selected products in local storage and log them to the database for the user session.
- [x] Add a dedicated settings page for managing product selections.
- [x] Collect statistics on how many users have which software.

- [x] Fix the tables in admin to be TanStack / NuxtUI3 compatible — columns require an `id` when using a non-string header.


## Duplicates
- [x] Normalise catalog product names to strip patch-level version suffixes so the software selection list avoids Chrome/Windows duplicates.
- there seesm to be a lot of duplciates e.g. this shouod be just Google Chrome not so many versions in the software slection list
Chrome 137.0.7151.68 <137.0.7151.68	Google	0	ENISA	Add to focus
Chrome 138.0.7204.157 <138.0.7204.157	Google	0	ENISA	Add to focus
Chrome 138.0.7204.96 <138.0.7204.96	Google	0	ENISA	Add to focus
Chrome 140.0.7339.185 <140.0.7339.185
- same for windows but for iwnow it makes sense to make a difrecne betweee nmajor version like windows 11 10 and sefer and so on but not so detiale

Windows 11 22H2 10.0.22621.0 <10.0.22621.5335	Microsoft	0	ENISA	Add to focus
Windows 11 22H2 10.0.22621.0 <10.0.22621.674	Microsoft	0	ENISA	Add to focus
Windows 11 22H3 10.0.22631.0 <10.0.22631.3880	Microsoft	0	ENISA	Add to focus
Windows 11 23H2 10.0.22631.0 <10.0.22631.3296	Microsoft	0	ENISA	Add to focus
Windows 11 23H2 10.0.22631.0 <10.0.22631.5039	Microsoft	0	ENISA	Add to focus
Windows 11 24H2 10.0.26100.0 <10.0.26100.2894	Microsoft	0	ENISA	Add to focus
Windows 7 For X64-based Systems Service Pack 1

we want to concentraton products and major versions not evdry little thing

Office/WordPad Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, And Windows 8.1	

## Layout
- [x] add a max-w-xs to the software title table column if not we have to scrol lto see the add button and son it should fit neatla

- [ ] Revise the layout especiall the fitlering stuff. it seems to me it takes too much space aawafr om show ign the actually results
- [ ] can weh show a floating roudned long pill that shwos the current active fitlers and allows to remove them and shiws somw dense statistixs?
- [] and also can we make the risk snapshot expandable (use nuxt ui 4) so we dont show  the CVSS severity mix
 and the lastest additions (and we should show the the 3 3latest additions here 
- [ ] the trend explore should also not to much spacd and be collapsoble some how or a modal i dont know. 
- [ ] the impot stuff should be on the admin page Data freshness

Last imported release: 2025-10-19 14:58

1,443 entries cached locally for instant filte
- [ ] but there should stil be an indicator when the data was last importeed in the index page
- [ ] the filter focus, tend explorer and filters should be open slideover so the focus can be on the data and not on the filter-mabye in a pageaside compnent and a navigationmenu  or toolbar that just has the icosn wiht hover tooltips?


## Performance

- [x] cache the downloaded data from enisa and kev for one day so we dont need to redownlaod durign the development all the time but can do a fast reimport add a second button for just reimporting
- [ ] enhance performance by precalculating as much as possibel. when i switch my software it takes a long time to rerender. show a laoding incdicator or somethign at least or make it blatzing fast 
- [x] make the bade from focus on my software just show the title not twice the title orasomeith Focus on my software
