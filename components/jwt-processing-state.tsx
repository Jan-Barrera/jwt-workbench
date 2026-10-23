"use client";

import type { VerifyJwtResult } from "@/lib/jwt/verify";
import type { ValidationCheck } from "@/lib/jwt/validate";

type JwtProcessingStateProps = {
  decoded: boolean;
  validationChecks: ValidationCheck[] | null;
  verifyResult: VerifyJwtResult | null;
};

/**
 * Surfaces the three independent JWT processing stages required by the NFR spec:
 * decoded (structure), evaluated (claim checks), and cryptographically verified.
 */
export function JwtProcessingState({
  decoded,
  validationChecks,
  verifyResult,
}: JwtProcessingStateProps) {
  if (!decoded && !validationChecks) {
    return null;
  }

  const evaluated = summarizeValidation(validationChecks, decoded);
  const verified = summarizeVerification(verifyResult);

  return (
    <div
      className="flex flex-col gap-2 rounded-lg border border-zinc-200 bg-white px-3 py-3 dark:border-zinc-800 dark:bg-zinc-900/40"
      aria-label="JWT processing state"
    >
      <p className="text-xs font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
        Processing state
      </p>
      <ul className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:gap-3">
        <StateItem
          label="Decoded"
          detail={
            decoded
              ? "Header and payload JSON parsed locally"
              : "Token could not be decoded"
          }
          status={decoded ? "active" : "error"}
        />
        <StateItem
          label="Evaluated"
          detail={evaluated.detail}
          status={evaluated.status}
        />
        <StateItem
          label="Verified"
          detail={verified.detail}
          status={verified.status}
          live
        />
      </ul>
    </div>
  );
}

type StateStatus = "active" | "warning" | "error" | "inactive" | "pending";

function StateItem({
  label,
  detail,
  status,
  live = false,
}: {
  label: string;
  detail: string;
  status: StateStatus;
  live?: boolean;
}) {
  return (
    <li className="flex min-w-[10rem] flex-1 flex-col gap-1">
      <span
        className={`inline-flex w-fit rounded-full px-2.5 py-0.5 text-xs font-semibold ${stateStyles(status)}`}
      >
        {label}
      </span>
      <span
        className="text-xs text-zinc-600 dark:text-zinc-400"
        {...(live ? { "aria-live": "polite" as const } : {})}
      >
        {detail}
      </span>
    </li>
  );
}

function stateStyles(status: StateStatus): string {
  switch (status) {
    case "active":
      return "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200";
    case "warning":
      return "bg-amber-100 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100";
    case "error":
      return "bg-red-100 text-red-900 dark:bg-red-950/60 dark:text-red-200";
    case "pending":
      return "bg-sky-100 text-sky-900 dark:bg-sky-950/50 dark:text-sky-200";
    case "inactive":
      return "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
  }
}

function summarizeValidation(
  checks: ValidationCheck[] | null,
  decoded: boolean,
): { status: StateStatus; detail: string } {
  if (!checks || checks.length === 0) {
    return {
      status: "inactive",
      detail: "Validation checks run after input is provided",
    };
  }

  const structure = checks.find((check) => check.id === "structure");
  if (structure?.outcome === "fail") {
    return {
      status: "error",
      detail: "Token structure is invalid",
    };
  }

  if (!decoded) {
    return {
      status: "inactive",
      detail: "Payload validation requires a decodable token",
    };
  }

  const actionable = checks.filter(
    (check) =>
      check.id !== "structure" &&
      check.id !== "signature" &&
      check.outcome !== "skipped" &&
      check.outcome !== "info",
  );
  const failures = actionable.filter((check) => check.outcome === "fail");
  const warnings = actionable.filter((check) => check.outcome === "warning");
  const notVerified = checks.some((check) => check.outcome === "not_verified");

  if (failures.length > 0) {
    return {
      status: "error",
      detail: `${failures.length} validation check${failures.length === 1 ? "" : "s"} failed`,
    };
  }
  if (warnings.length > 0) {
    return {
      status: "warning",
      detail: `${warnings.length} warning${warnings.length === 1 ? "" : "s"} from validation checks`,
    };
  }
  if (notVerified) {
    return {
      status: "pending",
      detail: "Structure and claims checked; signature not verified yet",
    };
  }
  return {
    status: "active",
    detail: "Structure and claim checks completed",
  };
}

function summarizeVerification(
  result: VerifyJwtResult | null,
): { status: StateStatus; detail: string } {
  if (!result || result.code === "MISSING_KEY") {
    return {
      status: "pending",
      detail: "Cryptographic check requires key material",
    };
  }
  if (result.code === "PASS") {
    return {
      status: "active",
      detail: `Signature verified with ${result.algorithm ?? "declared algorithm"}`,
    };
  }
  if (result.code === "INVALID_SIGNATURE") {
    return {
      status: "error",
      detail: "Signature does not match the supplied key",
    };
  }
  return {
    status: "warning",
    detail: result.message,
  };
}
