"use client";

import type { ValidationCheck, ValidationOutcome } from "@/lib/jwt/validate";

type JwtValidationPanelProps = {
  checks: ValidationCheck[];
};

export function JwtValidationPanel({ checks }: JwtValidationPanelProps) {
  return (
    <ul className="flex flex-col gap-2">
      {checks.map((check) => (
        <li
          key={check.id}
          className="rounded-lg border border-zinc-200 bg-white px-3 py-3 dark:border-zinc-800 dark:bg-zinc-900/40"
        >
          <div className="flex flex-wrap items-start justify-between gap-2">
            <span className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
              {check.label}
            </span>
            <OutcomeBadge outcome={check.outcome} />
          </div>
          <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
            {check.message}
          </p>
          {(check.expected !== undefined || check.actual !== undefined) && (
            <dl className="mt-2 grid gap-1 text-xs text-zinc-600 dark:text-zinc-400 sm:grid-cols-2">
              {check.expected !== undefined && (
                <div>
                  <dt className="font-medium text-zinc-700 dark:text-zinc-300">
                    Expected
                  </dt>
                  <dd className="font-mono break-all">{check.expected}</dd>
                </div>
              )}
              {check.actual !== undefined && (
                <div>
                  <dt className="font-medium text-zinc-700 dark:text-zinc-300">
                    Received
                  </dt>
                  <dd className="font-mono break-all">{check.actual}</dd>
                </div>
              )}
            </dl>
          )}
        </li>
      ))}
    </ul>
  );
}

const OUTCOME_LABELS: Record<ValidationOutcome, string> = {
  pass: "Pass",
  fail: "Fail",
  warning: "Warning",
  info: "Info",
  not_verified: "Not verified",
  skipped: "Skipped",
};

const OUTCOME_STYLES: Record<ValidationOutcome, string> = {
  pass:
    "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200",
  fail: "bg-red-100 text-red-900 dark:bg-red-950/60 dark:text-red-200",
  warning:
    "bg-amber-100 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100",
  info: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  not_verified:
    "bg-sky-100 text-sky-900 dark:bg-sky-950/50 dark:text-sky-200",
  skipped:
    "bg-zinc-100 text-zinc-600 dark:bg-zinc-800/80 dark:text-zinc-400",
};

function OutcomeBadge({ outcome }: { outcome: ValidationOutcome }) {
  return (
    <span
      className={`inline-flex shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${OUTCOME_STYLES[outcome]}`}
    >
      {OUTCOME_LABELS[outcome]}
    </span>
  );
}
