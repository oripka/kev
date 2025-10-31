import type { CatalogSource } from "~/types";
import type { SourceBadgeMap } from "~/types/dashboard";

export const catalogSourceLabels: Record<CatalogSource, string> = {
  kev: "CISA KEV",
  enisa: "ENISA",
  historic: "Historic dataset",
  custom: "Curated research",
  metasploit: "Metasploit",
  poc: "GitHub PoCs",
  market: "Market intelligence",
};

export const catalogSourceBadgeMap: SourceBadgeMap = {
  kev: { label: catalogSourceLabels.kev, color: "primary" },
  enisa: { label: catalogSourceLabels.enisa, color: "secondary" },
  historic: { label: catalogSourceLabels.historic, color: "warning" },
  custom: { label: catalogSourceLabels.custom, color: "info" },
  metasploit: { label: catalogSourceLabels.metasploit, color: "info" },
  poc: { label: catalogSourceLabels.poc, color: "success" },
  market: { label: catalogSourceLabels.market, color: "neutral" },
};
