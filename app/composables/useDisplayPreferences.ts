import { useLocalStorage } from "@vueuse/core";

type DateFormatPreference = "american" | "european";

type DisplayPreferences = {
  dateFormat: DateFormatPreference;
  showTime: boolean;
};

const defaultPreferences: DisplayPreferences = {
  dateFormat: "american",
  showTime: false,
};

export const useDisplayPreferences = () =>
  useLocalStorage<DisplayPreferences>("display-preferences", defaultPreferences, {
    mergeDefaults: true,
  });
