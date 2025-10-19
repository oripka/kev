# TODO

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