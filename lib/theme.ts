export type Theme = "light" | "dark" | "system";

export const THEME_STORAGE_KEY = "jwt-workbench-theme";

export function isTheme(value: string | null): value is Theme {
  return value === "light" || value === "dark" || value === "system";
}

export function readStoredTheme(): Theme {
  if (typeof window === "undefined") {
    return "system";
  }
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

export function prefersDarkColorScheme(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function shouldUseDarkTheme(theme: Theme, prefersDark = prefersDarkColorScheme()): boolean {
  if (theme === "dark") return true;
  if (theme === "light") return false;
  return prefersDark;
}

export function applyThemeToDocument(theme: Theme, prefersDark = prefersDarkColorScheme()): void {
  const dark = shouldUseDarkTheme(theme, prefersDark);
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.style.colorScheme = dark ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", theme);
}
