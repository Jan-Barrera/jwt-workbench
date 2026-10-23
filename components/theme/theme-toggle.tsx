"use client";

import { useCallback, useEffect, useLayoutEffect, useState } from "react";

import {
  applyThemeToDocument,
  readStoredTheme,
  type Theme,
  THEME_STORAGE_KEY,
} from "@/lib/theme";

const OPTIONS: { value: Theme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

const OPTION_IDS = OPTIONS.map((option) => option.value);

/** Syncs aria-pressed with localStorage before hydration so it matches React state. */
const TOGGLE_SCRIPT = `{var k=${JSON.stringify(THEME_STORAGE_KEY)};var t=null;try{t=localStorage.getItem(k)}catch(e){}if(t!=="light"&&t!=="dark"&&t!=="system")t="system";${JSON.stringify(OPTION_IDS)}.forEach(function(s){var el=document.getElementById("theme-option-"+s);if(el)el.setAttribute("aria-pressed",s===t?"true":"false")})}`;

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => readStoredTheme());

  useLayoutEffect(() => {
    applyThemeToDocument(readStoredTheme());
  }, []);

  useEffect(() => {
    if (theme !== "system") {
      return;
    }

    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyThemeToDocument("system");

    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [theme]);

  const selectTheme = useCallback((next: Theme) => {
    setTheme(next);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // ignore quota / private mode
    }
    applyThemeToDocument(next);
  }, []);

  return (
    <div className="inline-flex">
      <fieldset className="inline-flex rounded-lg border border-zinc-200 bg-zinc-50 p-0.5 dark:border-zinc-700 dark:bg-zinc-800/80">
        <legend className="sr-only">Color theme</legend>
        {OPTIONS.map((option) => {
          const active = theme === option.value;
          return (
            <button
              key={option.value}
              id={`theme-option-${option.value}`}
              type="button"
              data-theme-choice={option.value}
              onClick={() => selectTheme(option.value)}
              aria-pressed={active}
              className="theme-option"
            >
              {option.label}
            </button>
          );
        })}
      </fieldset>
      <script
        type={typeof window === "undefined" ? "text/javascript" : "text/plain"}
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: TOGGLE_SCRIPT }}
      />
    </div>
  );
}
