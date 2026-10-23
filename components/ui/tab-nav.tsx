"use client";

import { useCallback, useRef, type KeyboardEvent } from "react";

export type TabNavItem<T extends string> = {
  id: T;
  label: string;
};

type TabNavProps<T extends string> = {
  items: readonly TabNavItem<T>[];
  value: T;
  onChange: (id: T) => void;
  ariaLabel: string;
  className?: string;
};

export function TabNav<T extends string>({
  items,
  value,
  onChange,
  ariaLabel,
  className,
}: TabNavProps<T>) {
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const focusTab = useCallback((index: number) => {
    const tab = tabRefs.current[index];
    tab?.focus();
  }, []);

  const onKeyDown = useCallback(
    (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
      const last = items.length - 1;
      let next = index;

      switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
          next = index === last ? 0 : index + 1;
          break;
        case "ArrowLeft":
        case "ArrowUp":
          next = index === 0 ? last : index - 1;
          break;
        case "Home":
          next = 0;
          break;
        case "End":
          next = last;
          break;
        default:
          return;
      }

      event.preventDefault();
      onChange(items[next].id);
      focusTab(next);
    },
    [focusTab, items, onChange],
  );

  return (
    <nav
      className={
        className ??
        "flex flex-wrap gap-1 rounded-lg border border-zinc-200 bg-white p-1 dark:border-zinc-800 dark:bg-zinc-900/60"
      }
      aria-label={ariaLabel}
      role="tablist"
    >
      {items.map((item, index) => {
        const active = value === item.id;
        return (
          <button
            key={item.id}
            ref={(el) => {
              tabRefs.current[index] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${item.id}`}
            aria-selected={active}
            aria-controls={`tabpanel-${item.id}`}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(item.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={`rounded-md px-4 py-2 text-sm font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 ${
              active
                ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
            }`}
          >
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}

export function TabPanel({
  id,
  labelledBy,
  children,
  className,
}: {
  id: string;
  labelledBy: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      id={id}
      role="tabpanel"
      aria-labelledby={labelledBy}
      tabIndex={-1}
      className={className}
    >
      {children}
    </div>
  );
}
