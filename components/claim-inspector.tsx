"use client";

import { useMemo } from "react";

import {
  inspectPayloadClaims,
  type ClaimValidityStatus,
  type InspectedClaim,
} from "@/lib/jwt/claims";

type ClaimInspectorProps = {
  payload: unknown;
};

export function ClaimInspector({ payload }: ClaimInspectorProps) {
  const claims = useMemo(
    () => inspectPayloadClaims(payload, new Date()),
    [payload],
  );

  if (claims.length === 0) {
    return (
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        No object claims to inspect in this payload.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
      <table className="w-full min-w-[640px] border-collapse text-left text-sm">
        <caption className="sr-only">JWT payload claims</caption>
        <thead className="bg-zinc-100 text-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
          <tr>
            <th scope="col" className="px-3 py-2 font-semibold">Claim</th>
            <th scope="col" className="px-3 py-2 font-semibold">Name</th>
            <th scope="col" className="px-3 py-2 font-semibold">Raw value</th>
            <th scope="col" className="px-3 py-2 font-semibold">Interpreted</th>
            <th scope="col" className="px-3 py-2 font-semibold">Status</th>
          </tr>
        </thead>
        <tbody>
          {claims.map((claim) => (
            <ClaimRow key={claim.name} claim={claim} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ClaimRow({ claim }: { claim: InspectedClaim }) {
  return (
    <tr className="border-t border-zinc-200 dark:border-zinc-800">
      <td className="align-top px-3 py-3 font-mono text-zinc-900 dark:text-zinc-100">
        <div>{claim.name}</div>
        {claim.description && (
          <p className="mt-1 max-w-[14rem] font-sans text-xs text-zinc-500 dark:text-zinc-400">
            {claim.description}
          </p>
        )}
      </td>
      <td className="align-top px-3 py-3 text-zinc-800 dark:text-zinc-200">
        {claim.friendlyName ?? "—"}
      </td>
      <td className="align-top px-3 py-3 font-mono text-zinc-800 break-all dark:text-zinc-200">
        {claim.rawValue}
      </td>
      <td className="align-top px-3 py-3 whitespace-pre-line text-zinc-700 dark:text-zinc-300">
        {claim.interpretedValue ?? "—"}
      </td>
      <td className="align-top px-3 py-3">
        {claim.statusLabel ? (
          <StatusBadge status={claim.status} label={claim.statusLabel} />
        ) : (
          <span className="text-zinc-400">—</span>
        )}
      </td>
    </tr>
  );
}

function StatusBadge({
  status,
  label,
}: {
  status: ClaimValidityStatus;
  label: string;
}) {
  const styles: Record<NonNullable<ClaimValidityStatus>, string> = {
    expired:
      "bg-red-100 text-red-900 dark:bg-red-950/60 dark:text-red-200",
    not_yet_valid:
      "bg-amber-100 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100",
    active:
      "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200",
  };

  const className =
    status === null
      ? "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
      : styles[status];

  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${className}`}
      role="status"
    >
      {label}
    </span>
  );
}
