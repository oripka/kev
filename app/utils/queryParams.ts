export const extractQueryString = (value: unknown): string | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return extractQueryString(value[value.length - 1]);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return null;
};

export const parseQueryBoolean = (value: unknown): boolean | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return parseQueryBoolean(value[value.length - 1]);
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value === 1;
  }

  if (typeof value === "string") {
    const normalised = value.trim().toLowerCase();
    if (!normalised) {
      return null;
    }

    if (normalised === "true" || normalised === "1") {
      return true;
    }

    if (normalised === "false" || normalised === "0") {
      return false;
    }
  }

  return null;
};

export const parseQueryInteger = (value: unknown): number | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return parseQueryInteger(value[value.length - 1]);
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    const parsed = Number.parseInt(trimmed, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }

  return null;
};

export const parseQueryFloat = (value: unknown): number | null => {
  if (Array.isArray(value)) {
    if (!value.length) {
      return null;
    }

    return parseQueryFloat(value[value.length - 1]);
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    const parsed = Number.parseFloat(trimmed);
    return Number.isNaN(parsed) ? null : parsed;
  }

  return null;
};

export const normaliseNumericRange = (
  minimum: number | null,
  maximum: number | null,
  defaults: readonly [number, number],
  clamp: (value: number) => number,
): [number, number] => {
  let start =
    typeof minimum === "number" && Number.isFinite(minimum)
      ? minimum
      : defaults[0];
  let end =
    typeof maximum === "number" && Number.isFinite(maximum)
      ? maximum
      : defaults[1];

  start = clamp(start);
  end = clamp(end);

  if (start > end) {
    [start, end] = [end, start];
  }

  return [start, end];
};
