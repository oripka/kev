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
    .replace(/\bpatch\s+\d+\b/gi, " ");

const normaliseProductLabel = (
  value: string | null | undefined,
  vendorLabel: string
): string => {
  const trimmed = cleanWhitespace(value ?? "");
  if (!trimmed) {
    return DEFAULT_PRODUCT;
  }

  const withoutVendor = stripVendorFromProduct(trimmed, vendorLabel);

  const withoutComparators = stripComparatorSuffix(withoutVendor);

  const withoutVersionKeywords = withoutComparators.replace(
    /(\bversion\b|\bver\.?\b|\bv\d[\w.-]*|\bbuild\b|\brelease\b)/gi,
    ""
  );

  const withoutSegments = stripVersionSegments(withoutVersionKeywords)
    .replace(/[.,;:]+$/g, " ");

  const withoutDescriptors = removeGenericProductDescriptors(withoutSegments);

  const withReplacements = applyProductTokenReplacements(withoutDescriptors);

  const cleaned = cleanWhitespace(withReplacements);
  if (!cleaned) {
    const fallback = cleanWhitespace(withoutComparators || withoutVendor);
    return applyProductSpecialCasing(toTitleCase(fallback || DEFAULT_PRODUCT));
  }

  return applyProductSpecialCasing(toTitleCase(cleaned));
};

export const normaliseVendorProduct = (
  input: {
    vendor?: string | null;
    product?: string | null;
  },
  fallbackVendor = DEFAULT_VENDOR,
  fallbackProduct = DEFAULT_PRODUCT
): NormalisedVendorProduct => {
  const vendorLabel = normaliseVendorLabel(input.vendor ?? fallbackVendor);
  const vendorKey = slugify(vendorLabel, "vendor-unknown");

  const productLabel = normaliseProductLabel(
    input.product ?? fallbackProduct,
    vendorLabel
  );

  const productKey = `${vendorKey}__${slugify(productLabel, "product-unknown")}`;

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
