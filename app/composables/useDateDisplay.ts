import { computed } from "vue";
import { format, isValid, parseISO } from "date-fns";
import { useDisplayPreferences } from "~/composables/useDisplayPreferences";

type DateInput = string | number | Date | null | undefined;

type FormatOptions = {
  fallback?: string;
  withTime?: boolean;
  preserveInputOnError?: boolean;
};

const parseDateInput = (value: DateInput): Date | null => {
  if (value == null) {
    return null;
  }

  if (value instanceof Date) {
    return isValid(value) ? value : null;
  }

  if (typeof value === "number") {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed.length) {
      return null;
    }

    const isoParsed = parseISO(trimmed);
    if (isValid(isoParsed)) {
      return isoParsed;
    }

    const timestamp = Date.parse(trimmed);
    if (!Number.isNaN(timestamp)) {
      const parsed = new Date(timestamp);
      return Number.isNaN(parsed.getTime()) ? null : parsed;
    }
  }

  return null;
};

export const useDateDisplay = () => {
  const preferences = useDisplayPreferences();

  const basePattern = computed(() =>
    preferences.value.dateFormat === "european" ? "d MMM yyyy" : "MMM d, yyyy"
  );

  const rangeStartPattern = computed(() =>
    preferences.value.dateFormat === "european" ? "d MMM" : "MMM d"
  );

  const dateTimePattern = computed(() =>
    preferences.value.dateFormat === "european" ? "d MMM yyyy HH:mm" : "MMM d, yyyy HH:mm"
  );

  const formatDate = (value: DateInput, options: FormatOptions = {}) => {
    const { fallback = "—", withTime, preserveInputOnError = true } = options;
    if (value == null) {
      return fallback;
    }

    const parsed = parseDateInput(value);
    if (!parsed) {
      if (preserveInputOnError && typeof value === "string") {
        return value;
      }
      return fallback;
    }

    const pattern = (withTime ?? preferences.value.showTime)
      ? dateTimePattern.value
      : basePattern.value;

    return format(parsed, pattern);
  };

  const formatDateOrNull = (value: DateInput, options: Omit<FormatOptions, "fallback"> = {}) => {
    const formatted = formatDate(value, { ...options, fallback: "" });
    return formatted === "" ? null : formatted;
  };

  const formatDateRange = (
    start: DateInput,
    end: DateInput,
    options: Omit<FormatOptions, "fallback"> & { fallback?: string } = {}
  ) => {
    const { fallback = "—", withTime, preserveInputOnError } = options;
    const parsedStart = parseDateInput(start);
    const parsedEnd = parseDateInput(end);

    if (!parsedStart && !parsedEnd) {
      return fallback;
    }

    if (!parsedStart) {
      return formatDate(end, { fallback, withTime, preserveInputOnError });
    }

    if (!parsedEnd) {
      return formatDate(start, { fallback, withTime, preserveInputOnError });
    }

    const includeTime = withTime ?? preferences.value.showTime;
    const endPattern = includeTime ? dateTimePattern.value : basePattern.value;
    const startPattern = includeTime
      ? endPattern
      : parsedStart.getFullYear() === parsedEnd.getFullYear()
        ? rangeStartPattern.value
        : endPattern;

    return `${format(parsedStart, startPattern)} – ${format(parsedEnd, endPattern)}`;
  };

  return {
    preferences,
    formatDate,
    formatDateOrNull,
    formatDateRange,
  };
};
