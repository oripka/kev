export type NormalisedName = {
  label: string;
  key: string;
};

export type NormalisedVendorProduct = {
  vendor: NormalisedName;
  product: NormalisedName & {
    vendorKey: string;
    vendorLabel: string;
  };
};

const DEFAULT_VENDOR = "Unknown";
const DEFAULT_PRODUCT = "Unknown";

const toTitleCase = (value: string) =>
  value
    .split(" ")
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");

const cleanWhitespace = (value: string) => value.replace(/\s+/g, " ").trim();

const removeDiacritics = (value: string) =>
  value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ß/g, "ss");

const ambiguousVendorPatterns: RegExp[] = [
  /^(?:n\/?a|none|unknown|unspecified)$/i,
  /^(?:not\s+applicable|not\s+available)$/i,
  /^(?:multiple\s+vendors?|various|generic)$/i,
];

const isAmbiguousVendor = (value: string): boolean =>
  ambiguousVendorPatterns.some((pattern) => pattern.test(value));

const inferVendorFromProduct = (value: string | null | undefined): string | null => {
  const cleaned = cleanWhitespace(value ?? "");
  if (!cleaned) {
    return null;
  }

  const lower = cleaned.toLowerCase();

  if (/\bmicrosoft\b/.test(lower)) {
    return "Microsoft";
  }

  if (/^(?:windows|win32k|smbv?1)\b/.test(lower)) {
    return "Microsoft";
  }

  if (/^(?:exchange|outlook|sharepoint)\b/.test(lower)) {
    return "Microsoft";
  }

  if (/(?:^|\b)(?:android|pixel|google play)\b/.test(lower)) {
    return "Android";
  }

  if (/(?:^|\b)(?:ios|ipados|macos|watchos|tvos|visionos|iphone|ipad)\b/.test(lower)) {
    return "Apple";
  }

  return null;
};

const applyProductTokenReplacements = (value: string): string => {
  const patterns: Array<[RegExp, string]> = [
    [/\bmac\s*os\s*x\b/gi, "macos"],
    [/\bmac\s*os\b/gi, "macos"],
    [/\bos\s*x\b/gi, "macos"],
    [/\bipad\s*os\b/gi, "ipados"],
    [/\biphone\s*os\b/gi, "ios"],
    [/\bvision\s*os\b/gi, "visionos"],
    [/\bwatch\s*os\b/gi, "watchos"],
    [/\btv\s*os\b/gi, "tvos"],
    [/\s*&\s*/g, " and "],
    [/\s*\/\s*/g, " / "],
  ];

  return patterns.reduce(
    (result, [pattern, replacement]) => result.replace(pattern, replacement),
    value
  );
};

const removeGenericProductDescriptors = (value: string): string => {
  const genericPatterns: RegExp[] = [
    /\bunspecified\b/gi,
    /\bnot\s+specified\b/gi,
    /\bnot\s+applicable\b/gi,
    /\bunknown\b/gi,
    /\bn\/?a\b/gi,
    /\btbd\b/gi,
  ];

  return genericPatterns.reduce(
    (result, pattern) => result.replace(pattern, " "),
    value
  );
};

const applyProductSpecialCasing = (value: string): string => {
  const replacements: Array<[RegExp, string]> = [
    [/\bIos\b/g, "iOS"],
    [/\bIpados\b/g, "iPadOS"],
    [/\bMacos\b/g, "macOS"],
    [/\bTvos\b/g, "tvOS"],
    [/\bWatchos\b/g, "watchOS"],
    [/\bVisionos\b/g, "visionOS"],
    [/\bIphone\b/g, "iPhone"],
    [/\bIpad\b/g, "iPad"],
    [/\bIpod\b/g, "iPod"],
    [/\bAnd\b/g, "and"],
    [/\bOr\b/g, "or"],
  ];

  return replacements.reduce(
    (result, [pattern, replacement]) => result.replace(pattern, replacement),
    value
  );
};

const slugify = (value: string, fallback: string) => {
  const cleaned = removeDiacritics(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return cleaned || fallback;
};

const normaliseVendorLabel = (value: string | null | undefined): string => {
  const trimmed = cleanWhitespace(value ?? "");
  if (!trimmed) {
    return DEFAULT_VENDOR;
  }

  const lower = trimmed.toLowerCase();
  const corporateSuffixes = [
    "inc",
    "inc.",
    "corp",
    "corp.",
    "corporation",
    "ltd",
    "ltd.",
    "co",
    "co.",
    "llc",
    "gmbh",
    "s.a.",
    "s.a",
  ];

  const tokens = lower.split(" ");
  if (tokens.length > 1) {
    const last = tokens[tokens.length - 1];
    if (corporateSuffixes.includes(last)) {
      tokens.pop();
    }
  }

  const rebuilt = tokens.join(" ");
  return toTitleCase(rebuilt || DEFAULT_VENDOR);
};

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const stripVendorFromProduct = (product: string, vendor: string): string => {
  const pattern = new RegExp(`^${escapeRegExp(vendor)}\\s+`, "i");
  return product.replace(pattern, "").trim();
};

const stripComparatorSuffix = (value: string): string =>
  value.replace(/\s*(?:<=|>=|<|>|=)\s*.+$/g, "").trim();

const stripVersionSegments = (value: string): string =>
  value
    .replace(/\b\d+(?:\.\d+){1,}\b/g, "")
    .replace(/\s*\([^)]*\)\s*/g, " ")
    .replace(/\bbuild\s+\d+\b/gi, " ")
    .replace(/\brelease\s+\d+\b/gi, " ")
    .replace(/\bpatch\s+\d+\b/gi, " ")
    .replace(/(?:\.|-)?rc\d+\b/gi, " ")
    .replace(/\brelease\s+candidate\s*\d*\b/gi, " ");

const removeVendorOccurrences = (product: string, vendor: string): string => {
  if (!vendor) {
    return product;
  }

  const pattern = new RegExp(`\\b${escapeRegExp(vendor)}\\b`, "gi");
  return product.replace(pattern, " ");
};

const removeCatalogNoise = (value: string): string => {
  const patterns: RegExp[] = [
    /\badd\s+to\s+focus\b.*$/gi,
    /\btracked\b.*$/gi,
    /\b(?:cisa\s+kev|cisa|enisa|historic)\b.*$/gi,
  ];

  return patterns.reduce((result, pattern) => result.replace(pattern, " "), value);
};

const stripRangeDescriptors = (value: string): string =>
  value.replace(
    /\b(?:prior\s+to|before|through|up\s+to|until|and\s+(?:earlier|prior))\b.*$/gi,
    " "
  );

const stripPlatformDescriptors = (value: string): string => {
  const patterns: RegExp[] = [
    /\bfor\s+(?:x(?:64|86)|(?:32|64)(?:-?bit)?|itanium|arm|powerpc|ppc|sparc)[^,;)]*(?:systems?|platforms?)\b/gi,
    /\bfor\s+(?:all\s+versions|all\s+builds|all\s+platforms|all\s+systems)\b/gi,
    /\bfor\s+(?:microsoft\s+)?(?:windows|linux|mac\s*os|macos|os\s*x|android|ios|ipad\s*os|watch\s*os|tv\s*os|vision\s*os|unix|solaris|aix|hp-ux|chrome\s*os)[^,;)]*/gi,
    /\bon\s+(?:microsoft\s+)?(?:windows|linux|mac\s*os|macos|os\s*x|android|ios|ipad\s*os|watch\s*os|tv\s*os|vision\s*os|unix|solaris|aix|hp-ux|chrome\s*os)[^,;)]*/gi,
    /\bservice\s+pack\s*\d+\b/gi,
    /\bsp\s*\d+\b/gi,
  ];

  return patterns.reduce((result, pattern) => result.replace(pattern, " "), value);
};

const selectPrimaryClause = (value: string): string => {
  const segments = value
    .split(/[,;|]/)
    .map((segment) => cleanWhitespace(segment))
    .filter(Boolean);

  if (segments.length === 0) {
    return value;
  }

  return segments[0];
};

const removeTrailingPlatformList = (value: string): string => {
  const platformPattern = /\b(windows|linux|mac\s*os|macos|os\s*x|android|ios|ipad\s*os|watch\s*os|tv\s*os|vision\s*os|unix|solaris|aix|hp-ux|chrome\s*os|ubuntu|red\s+hat|suse|debian)\b/gi;
  let match: RegExpExecArray | null = null;
  let trimmed = value;

  while ((match = platformPattern.exec(value)) !== null) {
    if (match.index > 0 && !value.toLowerCase().startsWith(match[0].toLowerCase())) {
      const prefix = value.slice(0, match.index);
      const trimmedPrefix = prefix.trimEnd();
      const precedingChar = trimmedPrefix.slice(-1);
      const precedingWord = trimmedPrefix.split(/\s+/).pop()?.toLowerCase() ?? "";
      const shouldTrim =
        /[\/;:()\-]$/.test(precedingChar) ||
        precedingWord === "for" ||
        precedingWord === "on" ||
        precedingWord === "in" ||
        precedingWord === "to";

      if (shouldTrim) {
        trimmed = prefix;
        break;
      }
    }
  }

  return trimmed;
};

const dedupeAdjacentTokens = (value: string): string => {
  const tokens = value.split(" ").filter(Boolean);
  if (tokens.length <= 1) {
    return tokens.join(" ");
  }

  const deduped = tokens.filter((token, index) => {
    if (index === 0) {
      return true;
    }

    return tokens[index - 1].toLowerCase() !== token.toLowerCase();
  });

  return deduped.join(" ");
};

const normaliseLinuxLabel = (value: string, vendorLabel: string): string => {
  const vendorLower = vendorLabel.toLowerCase();
  const productLower = value.toLowerCase();
  const vendorMentionsLinux = vendorLower.includes("linux") || vendorLower === "kernel";
  const vendorMentionsKernel = vendorLower.includes("kernel") || vendorLower === "kernel";
  const productMentionsKernel = /\bkernel\b/i.test(productLower);
  const canonicalLinuxLabel = vendorMentionsKernel || productMentionsKernel ? "Linux Kernel" : "Linux";

  if (vendorMentionsLinux || productMentionsKernel) {
    if (!productLower || /^(patch|n\/a|unknown|unspecified)$/i.test(productLower)) {
      return canonicalLinuxLabel;
    }

    if (/^kernel$/i.test(productLower)) {
      return "Linux Kernel";
    }

    if (/^linux\s+kernel$/i.test(productLower)) {
      return "Linux Kernel";
    }

    if (/^linux$/i.test(productLower)) {
      return canonicalLinuxLabel;
    }

    const compactProduct = productLower.replace(/\s+/g, "");
    const looksLikeHash = /^[0-9a-f]{7,40}$/i.test(compactProduct);
    const isPatchDescriptor = /^patch(?:[:\s-]*(?:[0-9a-f]{7,40}|v?\d+(?:\.\d+)*))?$/i.test(productLower);
    const isNumericOnly = /^\d+(?:\.\d+)*$/i.test(productLower);
    const isZero = productLower === "0";
    const isLinuxWithNumericSuffix = /^linux(?:\s+kernel)?(?:\s+[0-9]+(?:[._-][0-9]+)*)?$/i.test(productLower);

    if (
      looksLikeHash ||
      isPatchDescriptor ||
      isNumericOnly ||
      isZero ||
      isLinuxWithNumericSuffix
    ) {
      return canonicalLinuxLabel;
    }
  }

  if (vendorLower === "kernel" && /\blinux\b/i.test(productLower)) {
    return "Linux Kernel";
  }

  if (/^linux\s+kernel\b/i.test(productLower)) {
    return "Linux Kernel";
  }

  return value;
};

const canonicaliseProductLabel = (
  label: string,
  vendorLabel: string,
  originalProduct: string
): string => {
  const normalisedLabel = cleanWhitespace(label);
  if (!normalisedLabel) {
    return label;
  }

  const labelLower = normalisedLabel.toLowerCase();
  const vendorLower = vendorLabel.toLowerCase();
  const originalLower = cleanWhitespace(originalProduct).toLowerCase();

  if (vendorLower === "microsoft") {
    if (
      /\bwin32k\b/.test(labelLower) ||
      /\bwindows\s+win32k\b/.test(labelLower) ||
      /\bwindows\s+kernel\b/.test(labelLower) ||
      /\bsmbv?1\b/.test(labelLower) ||
      /\bwin32k\b/.test(originalLower) ||
      /\bsmbv?1\b/.test(originalLower)
    ) {
      return "Windows";
    }
  }

  if (vendorLower === "android") {
    if (
      labelLower === "kernel" ||
      /\bandroid\s+kernel\b/.test(labelLower) ||
      /\blinux\s+kernel\b/.test(labelLower) ||
      /\bandroind\b/.test(labelLower) ||
      /\bandroid\s+kernel\b/.test(originalLower)
    ) {
      return "Android";
    }
  }

  if (vendorLower === "apple") {
    if (labelLower === "ios and") {
      return "iOS";
    }
  }

  return normalisedLabel;
};

const buildFallbackProductLabel = (
  source: string,
  vendorLabel: string
): string => {
  const prepared = cleanWhitespace(source || "");
  const baseCandidate = prepared || "";
  const base = /^(?:patch:?|n\/a|unknown|unspecified)$/i.test(baseCandidate)
    ? vendorLabel
    : /^\d+$/.test(baseCandidate)
      ? vendorLabel
      : baseCandidate || vendorLabel || DEFAULT_PRODUCT;
  const specialCased = applyProductSpecialCasing(toTitleCase(base));
  return normaliseLinuxLabel(specialCased, vendorLabel);
};

const normaliseProductLabel = (
  value: string | null | undefined,
  vendorLabel: string
): string => {
  const trimmed = cleanWhitespace(value ?? "");
  if (!trimmed) {
    return DEFAULT_PRODUCT;
  }

  const withoutVendor = stripVendorFromProduct(trimmed, vendorLabel);
  const withoutEmbeddedVendor = removeVendorOccurrences(withoutVendor, vendorLabel);
  const withoutCatalogNoise = removeCatalogNoise(withoutEmbeddedVendor);
  const primaryClause = selectPrimaryClause(withoutCatalogNoise);
  const withoutComparators = stripComparatorSuffix(primaryClause);
  const fallbackLabel = buildFallbackProductLabel(
    withoutComparators || withoutVendor,
    vendorLabel
  );
  const withoutRangeDescriptors = stripRangeDescriptors(withoutComparators);
  const withoutVersionKeywords = withoutRangeDescriptors.replace(
    /(\bversion\b|\bver\.?\b|\bv\d[\w.-]*|\bbuild\b|\brelease\b)/gi,
    ""
  );
  const withoutPlatforms = stripPlatformDescriptors(withoutVersionKeywords);
  const withoutSegments = stripVersionSegments(withoutPlatforms).replace(/[.,;:]+$/g, " ");
  const withoutDescriptors = removeGenericProductDescriptors(withoutSegments);
  const withoutTrailingPlatforms = removeTrailingPlatformList(withoutDescriptors);
  const withReplacements = applyProductTokenReplacements(withoutTrailingPlatforms);
  const deduped = dedupeAdjacentTokens(withReplacements);
  const cleaned = cleanWhitespace(deduped);
  if (!cleaned) {
    return fallbackLabel;
  }

  const specialCased = applyProductSpecialCasing(toTitleCase(cleaned));
  const normalised = normaliseLinuxLabel(specialCased, vendorLabel);
  const fallbackMeaningful =
    /^(?:patch:?|n\/a|unknown|unspecified)$/i.test(fallbackLabel) ||
    /^\d+$/.test(fallbackLabel)
      ? DEFAULT_PRODUCT
      : fallbackLabel;

  if (
    /^(?:patch:?|n\/a|unknown|unspecified)$/i.test(normalised) ||
    /^\d+$/.test(normalised)
  ) {
    return fallbackMeaningful;
  }

  return normalised;
};

export const normaliseVendorProduct = (
  input: {
    vendor?: string | null;
    product?: string | null;
  },
  fallbackVendor = DEFAULT_VENDOR,
  fallbackProduct = DEFAULT_PRODUCT
): NormalisedVendorProduct => {
  const originalVendor = input.vendor ?? fallbackVendor;
  const originalProduct = input.product ?? fallbackProduct;
  const vendorSource = cleanWhitespace(originalVendor ?? "");
  const ambiguousVendor = !vendorSource || isAmbiguousVendor(vendorSource);

  let vendorLabel = normaliseVendorLabel(originalVendor ?? fallbackVendor);
  if (vendorLabel === DEFAULT_VENDOR || ambiguousVendor) {
    const inferredVendor = inferVendorFromProduct(originalProduct);
    if (inferredVendor) {
      vendorLabel = normaliseVendorLabel(inferredVendor);
    } else if (ambiguousVendor) {
      vendorLabel = DEFAULT_VENDOR;
    }
  }

  const vendorKey = slugify(vendorLabel, "vendor-unknown");

  const rawProductLabel = normaliseProductLabel(originalProduct, vendorLabel);
  const productLabel = canonicaliseProductLabel(
    rawProductLabel,
    vendorLabel,
    originalProduct
  );

  const productKey = `${vendorKey}__${slugify(
    productLabel,
    "product-unknown"
  )}`;

  return {
    vendor: {
      label: vendorLabel,
      key: vendorKey,
    },
    product: {
      label: productLabel,
      key: productKey,
      vendorKey,
      vendorLabel,
    },
  };
};
