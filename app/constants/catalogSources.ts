import type { CatalogSource } from "~/types";
import type { SourceBadgeMap } from "~/types/dashboard";

export const catalogSourceLabels: Record<CatalogSource, string> = {
  kev: "CISA KEV",
  enisa: "ENISA",
  historic: "Historic dataset",
  metasploit: "Metasploit",
};

export const catalogSourceBadgeMap: SourceBadgeMap = {
  kev: { label: catalogSourceLabels.kev, color: "primary" },
  enisa: { label: catalogSourceLabels.enisa, color: "secondary" },
  historic: { label: catalogSourceLabels.historic, color: "warning" },
  metasploit: { label: catalogSourceLabels.metasploit, color: "info" },
};
