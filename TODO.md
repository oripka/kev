# TODO

some of these might already be implmented if yes just check - [x] them . if not fix it 

- [ ] Add a ransomware spotlight filter state, active filter chips, and UI controls so users can focus the dashboard on ransomware-linked CVEs.
- [ ] Ensure the query payload includes the new parameter.
- [ ] Add an option to show trend lines for the filtered vulnerabilities (to visualize frequency over time, use Univis).
- [ ] Implement this trend-line option as a toggle switch in the UI.

- [ ] Create a category / edge for items typically exposed on the open internet (e.g. SSL VPN, Citrix ADC, Exchange, web apps, etc.).
- [ ] Identify and define reliable indicators to make this category accurate and consistent.

- [ ] Move the diagram into its own component.
- [ ] Refactor and decompose where it makes sense to improve structure and maintainability.

- [ ] Fix the “Add to my software” function — currently not working.
- [ ] Improve dropdown performance (currently very slow).
- [ ] Store imported software data in a database table during import (from KEV and ENISA).
- [ ] Create a separate configuration page for this and link it in the header.

- [ ] Fix the “Add to product list” button — currently does nothing even after selecting a product.
- [ ] Ensure it updates the number of selected products.
- [ ] Save selected products in local storage and log them to the database for the user session.
- [ ] Add a dedicated settings page for managing product selections.
- [ ] Collect statistics on how many users have which software.

- [] fix the tables in admin to be tanstack  / nuxtui3 compatble Columns require an id when using a non-string header



## Performance

- [ ] enhance performance by precalculating as much as possibel. when i switch my software it takes a long time to rerender. show a laoding incdicator or somethign at least or make it blatzing fast 
- [ ] make the bade from focus on my software just show the title not twice the title orasomeith Focus on my software
- [ ] add a max-w-xs to the software title table column if not we have to scrol lto see the add button and son it should fit neatla

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