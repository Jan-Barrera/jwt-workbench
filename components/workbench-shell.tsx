"use client";

import { useState } from "react";

import { TabNav, TabPanel } from "@/components/ui/tab-nav";

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

const VIEWS = [
  { id: "decoder" as const, label: "Decoder" },
  { id: "debugger" as const, label: "Debugger" },
  { id: "compare" as const, label: "Compare" },
  { id: "generator" as const, label: "Generator" },
  { id: "utilities" as const, label: "Utilities" },
] as const;

export function WorkbenchShell() {
  const [view, setView] = useState<WorkbenchView>("decoder");

  return (
    <div className="flex flex-col gap-6">
      <TabNav
        items={VIEWS}
        value={view}
        onChange={setView}
        ariaLabel="Workbench tools"
      />
      <TabPanel id={`tabpanel-${view}`} labelledBy={`tab-${view}`}>
        {view === "decoder" && <JwtDecoder />}
        {view === "debugger" && <JwtDebugger />}
        {view === "compare" && <JwtCompare />}
        {view === "generator" && <JwtGenerator />}
        {view === "utilities" && <DeveloperUtilities />}
      </TabPanel>
    </div>
  );
}
