"use client";

import { useMemo, useState } from "react";

import { PrivacyToolbar } from "@/components/privacy/privacy-toolbar";
import {
  compareJwts,
  filterChangedFields,
  type CompareFieldDiff,
  type CompareFieldKind,
  type CompareSection,
} from "@/lib/jwt/compare";

const PLACEHOLDER =
  "Paste a compact JWT (header.payload.signature) or Bearer token…";

export function JwtCompare() {
  const [tokenA, setTokenA] = useState("");
  const [tokenB, setTokenB] = useState("");
  const [changedOnly, setChangedOnly] = useState(false);

  const result = useMemo(() => {
    if (!tokenA.trim() || !tokenB.trim()) return null;
    return compareJwts(tokenA, tokenB);
  }, [tokenA, tokenB]);

  const hasSensitiveState = Boolean(tokenA) || Boolean(tokenB);

  const clear = () => {
    setTokenA("");
    setTokenB("");
    setChangedOnly(false);
  };

  return (
    <div className="flex w-full flex-col gap-8">
      <PrivacyToolbar
        description="Compares decoded header and payload JSON only. Signature differences are reported separately and do not imply claim changes."
        onClear={clear}
        canClear={hasSensitiveState}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <TokenInput
          id="jwt-compare-a"
          label="Token A"
          value={tokenA}
          onChange={setTokenA}
        />
        <TokenInput
          id="jwt-compare-b"
          label="Token B"
          value={tokenB}
          onChange={setTokenB}
        />
      </div>

      {result && !result.ok && (
        <p
          className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200"
          role="alert"
        >
          Token {result.token} could not be decoded: {result.error}
        </p>
      )}

      {result?.ok && (
        <>
          {result.signaturesDiffer && (
            <p
              className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-100"
              role="status"
            >
              Encoded signatures differ. Header and payload comparisons reflect
              decoded JSON only.
            </p>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              Showing side-by-side raw values with optional friendly timestamps.
            </p>
            <label className="inline-flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
              <input
                type="checkbox"
                checked={changedOnly}
                onChange={(event) => setChangedOnly(event.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 text-zinc-900 focus:ring-zinc-400 dark:border-zinc-600 dark:bg-zinc-950"
              />
              Changed fields only
            </label>
          </div>

          <CompareSectionPanel
            title="Header"
            section={result.header}
            changedOnly={changedOnly}
          />
          <CompareSectionPanel
            title="Payload"
            section={result.payload}
            changedOnly={changedOnly}
          />
        </>
      )}
    </div>
  );
}

type TokenInputProps = {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
};

function TokenInput({ id, label, value, onChange }: TokenInputProps) {
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={id} className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
        {label}
      </label>
      <textarea
        id={id}
        name={id}
        rows={4}
        spellCheck={false}
        autoComplete="off"
        placeholder={PLACEHOLDER}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full resize-y rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 shadow-sm outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
      />
    </div>
  );
}

type CompareSectionPanelProps = {
  title: string;
  section: CompareSection;
  changedOnly: boolean;
};

function CompareSectionPanel({
  title,
  section,
  changedOnly,
}: CompareSectionPanelProps) {
  const fields = changedOnly
    ? filterChangedFields(section.fields)
    : section.fields;

  return (
    <section className="flex flex-col gap-3" aria-labelledby={`${title}-compare-heading`}>
      <div className="flex flex-col gap-1">
        <h2
          id={`${title}-compare-heading`}
          className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
        >
          {title}
        </h2>
        <SummaryBadges summary={section.summary} />
      </div>

      {fields.length === 0 ? (
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {changedOnly
            ? `No changed ${title.toLowerCase()} fields.`
            : `No ${title.toLowerCase()} fields to compare.`}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
          <table className="w-full min-w-[960px] border-collapse text-left text-sm">
            <caption className="sr-only">{title} comparison</caption>
            <thead className="bg-zinc-100 text-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
              <tr>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Field
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Status
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Token A (raw)
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Token A (interpreted)
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Token B (raw)
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Token B (interpreted)
                </th>
              </tr>
            </thead>
            <tbody>
              {fields.map((field) => (
                <CompareRow key={field.path} field={field} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function SummaryBadges({
  summary,
}: {
  summary: CompareSection["summary"];
}) {
  const items: Array<{ label: string; count: number; className: string }> = [
    {
      label: "changed",
      count: summary.changed,
      className:
        "bg-amber-100 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100",
    },
    {
      label: "added",
      count: summary.added,
      className:
        "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200",
    },
    {
      label: "removed",
      count: summary.removed,
      className: "bg-red-100 text-red-900 dark:bg-red-950/60 dark:text-red-200",
    },
    {
      label: "unchanged",
      count: summary.unchanged,
      className: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    },
  ];

  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item) => (
        <span
          key={item.label}
          className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${item.className}`}
        >
          {item.count} {item.label}
        </span>
      ))}
    </div>
  );
}

function CompareRow({ field }: { field: CompareFieldDiff }) {
  return (
    <tr className="border-t border-zinc-200 dark:border-zinc-800">
      <td className="align-top px-3 py-3 font-mono text-zinc-900 dark:text-zinc-100">
        {field.path}
      </td>
      <td className="align-top px-3 py-3">
        <KindBadge kind={field.kind} />
      </td>
      <td className="align-top px-3 py-3 font-mono break-all text-zinc-800 dark:text-zinc-200">
        {field.rawValueA ?? "—"}
      </td>
      <td className="align-top px-3 py-3 whitespace-pre-line text-zinc-700 dark:text-zinc-300">
        {field.interpretedValueA ?? "—"}
      </td>
      <td className="align-top px-3 py-3 font-mono break-all text-zinc-800 dark:text-zinc-200">
        {field.rawValueB ?? "—"}
      </td>
      <td className="align-top px-3 py-3 whitespace-pre-line text-zinc-700 dark:text-zinc-300">
        {field.interpretedValueB ?? "—"}
      </td>
    </tr>
  );
}

function KindBadge({ kind }: { kind: CompareFieldKind }) {
  const styles: Record<CompareFieldKind, string> = {
    changed:
      "bg-amber-100 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100",
    added:
      "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200",
    removed: "bg-red-100 text-red-900 dark:bg-red-950/60 dark:text-red-200",
    unchanged: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };

  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium capitalize ${styles[kind]}`}
    >
      {kind}
    </span>
  );
}
