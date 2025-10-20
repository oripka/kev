import type { QuickFilterPreset } from "~/types/dashboard";

export type FilterPresetContext = {
  currentYear: number;
  previousYear: number;
  defaultYearRange: readonly [number, number];
  sliderBounds: readonly [number, number];
  defaultCvssRange: readonly [number, number];
  defaultEpssRange: readonly [number, number];
};

const cloneRange = (range: readonly [number, number]): [number, number] => [
  range[0],
  range[1],
];

const clampToBounds = (value: number, bounds: readonly [number, number]) => {
  const [min, max] = bounds;
  if (!Number.isFinite(value)) {
    return Math.min(Math.max(0, min), max);
  }
  return Math.min(Math.max(value, min), max);
};

const normaliseYearRange = (
  start: number,
  end: number,
  bounds: readonly [number, number],
): [number, number] => {
  const first = clampToBounds(start, bounds);
  const second = clampToBounds(end, bounds);
  return first <= second ? [first, second] : [second, first];
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
  const {
    currentYear,
    previousYear,
    defaultYearRange,
    sliderBounds,
    defaultCvssRange,
    defaultEpssRange,
  } = context;

  const recentRange = normaliseYearRange(previousYear, currentYear, sliderBounds);

  return [
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
      id: "industrial-critical",
      label: "Industrial control critical",
      description: "ICS vulnerabilities with elevated severity this year.",
      icon: "i-lucide-circuit-board",
      color: "secondary",
      update: {
        filters: { domain: "Industrial Control Systems" },
        cvssRange: createCvssRange(7.5, defaultCvssRange),
        yearRange: recentRange,
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
    {
      id: "metasploit-ready",
      label: "Metasploit ready",
      description: "CVEs with public Metasploit modules available.",
      icon: "i-lucide-terminal",
      color: "primary",
      update: {
        source: "metasploit",
        epssRange: createEpssRange(40, defaultEpssRange),
        showAllResults: true,
      },
    },
    {
      id: "headline-zero-days",
      label: "Headline zero-days",
      description: "Named vulnerabilities from the last 12 months.",
      icon: "i-lucide-megaphone",
      color: "primary",
      update: {
        showWellKnownOnly: true,
        yearRange: recentRange,
        showAllResults: true,
      },
    },
    {
      id: "vpn-gateway-pressure",
      label: "VPN gateway pressure",
      description: "Remote access gear trending with ransomware crews.",
      icon: "i-lucide-shield-alert",
      color: "warning",
      update: {
        filters: { domain: "Networking & VPN" },
        showInternetExposedOnly: true,
        showRansomwareOnly: true,
        cvssRange: createCvssRange(7.5, defaultCvssRange),
      },
    },
    {
      id: "microsoft-patch-sprint",
      label: "Microsoft patch sprint",
      description: "Microsoft CVEs added over the past year.",
      icon: "i-lucide-building-2",
      color: "info",
      update: {
        filters: { vendor: "microsoft" },
        yearRange: recentRange,
        cvssRange: createCvssRange(7, defaultCvssRange),
      },
    },
    {
      id: "cisco-network-core",
      label: "Cisco network core",
      description: "Cisco networking flaws with high exploit likelihood.",
      icon: "i-lucide-network",
      color: "secondary",
      update: {
        filters: { vendor: "cisco" },
        cvssRange: createCvssRange(8, defaultCvssRange),
        epssRange: createEpssRange(50, defaultEpssRange),
        showInternetExposedOnly: true,
      },
    },
    {
      id: "catalog-default",
      label: "Catalog default",
      description: "Restore the catalog to the default balanced view.",
      icon: "i-lucide-rotate-ccw",
      color: "neutral",
      update: {
        filters: {
          domain: null,
          exploit: null,
          vulnerability: null,
          vendor: null,
          product: null,
        },
        search: "",
        source: "all",
        yearRange: cloneRange(defaultYearRange),
        cvssRange: cloneRange(defaultCvssRange),
        epssRange: cloneRange(defaultEpssRange),
        showWellKnownOnly: false,
        showRansomwareOnly: false,
        showInternetExposedOnly: false,
        showOwnedOnly: false,
        showAllResults: false,
      },
    },
  ];
};
