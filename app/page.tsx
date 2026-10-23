import { WorkbenchShell } from "@/components/workbench-shell";
import { LocalPrivacyIndicator } from "@/components/privacy/local-privacy-indicator";
import { ThemeToggle } from "@/components/theme/theme-toggle";

export default function Home() {
  return (
    <div className="min-h-full bg-zinc-50 dark:bg-zinc-950">
      <header className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mx-auto flex max-w-5xl flex-col gap-4 px-4 py-6 sm:px-6 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex flex-col gap-1">
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">
              JWT Workbench
            </h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              Decode, validate, verify, and generate JSON Web Tokens locally
            </p>
            <LocalPrivacyIndicator message="Local-first — tokens and keys stay in your browser by default" />
          </div>
          <ThemeToggle />
        </div>
      </header>
      <main id="main-content" className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        <WorkbenchShell />
      </main>
    </div>
  );
}
