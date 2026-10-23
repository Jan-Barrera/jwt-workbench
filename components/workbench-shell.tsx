"use client";

import { useState } from "react";

import { DeveloperUtilities } from "./developer-utilities";
import { JwtCompare } from "./jwt-compare";
import { JwtDebugger } from "./jwt-debugger";
import { JwtDecoder } from "./jwt-decoder";
import { JwtGenerator } from "./jwt-generator";

type WorkbenchView =
  | "decoder"
  | "compare"
  | "generator"
  | "debugger"
  | "utilities";

export function WorkbenchShell() {
  const [view, setView] = useState<WorkbenchView>("decoder");

  return (
    <div className="flex flex-col gap-6">
      <nav
        className="flex flex-wrap gap-1 rounded-lg border border-zinc-200 bg-white p-1 dark:border-zinc-800 dark:bg-zinc-900/60"
        aria-label="Workbench tools"
      >
        {(
          [
            { id: "decoder" as const, label: "Decoder" },
            { id: "debugger" as const, label: "Debugger" },
            { id: "compare" as const, label: "Compare" },
            { id: "generator" as const, label: "Generator" },
            { id: "utilities" as const, label: "Utilities" },
          ] as const
        ).map((tab) => {
          const active = view === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setView(tab.id)}
              aria-current={active ? "page" : undefined}
              className={`rounded-md px-4 py-2 text-sm font-medium transition ${
                active
                  ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                  : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </nav>
      {view === "decoder" && <JwtDecoder />}
      {view === "debugger" && <JwtDebugger />}
      {view === "compare" && <JwtCompare />}
      {view === "generator" && <JwtGenerator />}
      {view === "utilities" && <DeveloperUtilities />}
    </div>
  );
}
