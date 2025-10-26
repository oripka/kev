import type { QuickFilterPreset } from "~/types/dashboard";

export type FilterPresetContext = {
  currentYear: number;
  previousYear: number;
  defaultYearRange: readonly [number, number];
  sliderBounds: readonly [number, number];
  defaultCvssRange: readonly [number, number];
  defaultEpssRange: readonly [number, number];
};

const createCvssRange = (
  minimum: number,
  defaults: readonly [number, number],
): [number, number] => {
  const [min, max] = defaults;
  return [Math.max(minimum, min), max];
};

const createEpssRange = (
  minimum: number,
  defaults: readonly [number, number],
): [number, number] => {
  const [min, max] = defaults;
  return [Math.max(minimum, min), max];
};

export const createFilterPresets = (
  context: FilterPresetContext,
): QuickFilterPreset[] => {
  const { defaultCvssRange, defaultEpssRange } = context;

  return [
    {
      id: "public-exploit-ready",
      label: "Public exploit coverage",
      description: "CVEs with a Metasploit module or published GitHub proof of concept.",
      icon: "i-lucide-target",
      color: "info",
      update: {
        showPublicExploitOnly: true,
        showAllResults: true,
      },
    },
    {
      id: "ransomware-hot-list",
      label: "Ransomware hot list",
      description: "High-severity CVEs linked to confirmed ransomware operations.",
      icon: "i-lucide-flame",
      color: "warning",
      update: {
        showRansomwareOnly: true,
        cvssRange: createCvssRange(8, defaultCvssRange),
        epssRange: createEpssRange(60, defaultEpssRange),
        showAllResults: true,
      },
    },
    {
      id: "internet-edge-exposure",
      label: "Internet edge exposure",
      description: "Edge devices with confirmed internet exposure signals.",
      icon: "i-lucide-radar",
      color: "error",
      update: {
        filters: { domain: "Internet Edge" },
        showInternetExposedOnly: true,
        cvssRange: createCvssRange(7.5, defaultCvssRange),
        epssRange: createEpssRange(50, defaultEpssRange),
      },
    },
    {
      id: "server-rce-blitz",
      label: "Server-side RCE blitz",
      description: "Remote code execution chains targeting server workloads.",
      icon: "i-lucide-bolt",
      color: "error",
      update: {
        filters: { exploit: "RCE · Server-side Memory Corruption" },
        cvssRange: createCvssRange(8.5, defaultCvssRange),
        showAllResults: true,
      },
    },
  ];
};
