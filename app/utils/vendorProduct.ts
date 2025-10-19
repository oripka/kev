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

  const withoutSegments = stripVersionSegments(withoutVersionKeywords);

  const cleaned = cleanWhitespace(withoutSegments);
  if (!cleaned) {
    return toTitleCase(cleanWhitespace(withoutComparators || withoutVendor));
  }

  return toTitleCase(cleaned);
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
