"use client";

import { useMemo, useState, type ReactNode } from "react";

import { decodeBase64Url, encodeBase64Url } from "@/lib/util/base64url";
import { formatJson, type JsonFormatMode } from "@/lib/util/json-format";
import { inspectKeyMaterial, type InspectedKeyEntry } from "@/lib/util/key-inspect";
import { convertUnixTimestamp } from "@/lib/util/timestamp";

import { LocalPrivacyIndicator } from "@/components/privacy/local-privacy-indicator";

import { TabNav, TabPanel } from "@/components/ui/tab-nav";

import { CopyButton } from "./copy-button";

type UtilityTab = "base64url" | "timestamp" | "json" | "key";

const UTILITY_TABS = [
  { id: "base64url" as const, label: "Base64URL" },
  { id: "timestamp" as const, label: "Unix timestamp" },
  { id: "json" as const, label: "JSON formatter" },
  { id: "key" as const, label: "PEM / JWK" },
] as const;

const INPUT_CLASS =
  "w-full resize-y rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 shadow-sm outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100";

const OUTPUT_CLASS =
  "w-full resize-y rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 font-mono text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900/60 dark:text-zinc-100";

export function DeveloperUtilities() {
  const [tab, setTab] = useState<UtilityTab>("base64url");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">
          Developer utilities
        </h2>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          Small helpers for Base64URL, timestamps, JSON, and public key
          inspection. All processing runs locally in your browser.
        </p>
        <LocalPrivacyIndicator message="Local-only — nothing is sent to the server" />
      </div>

      <TabNav
        items={UTILITY_TABS}
        value={tab}
        onChange={setTab}
        ariaLabel="Developer utility tools"
      />

      <TabPanel id={`tabpanel-${tab}`} labelledBy={`tab-${tab}`}>
        {tab === "base64url" && <Base64UrlUtility />}
        {tab === "timestamp" && <TimestampUtility />}
        {tab === "json" && <JsonFormatterUtility />}
        {tab === "key" && <KeyInspectorUtility />}
      </TabPanel>
    </div>
  );
}

function Base64UrlUtility() {
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<"encode" | "decode">("decode");

  const result = useMemo(() => {
    if (!input.trim()) return null;
    return mode === "encode"
      ? encodeBase64Url(input)
      : decodeBase64Url(input);
  }, [input, mode]);

  return (
    <UtilityPanel
      title="Base64URL"
      description="Encode UTF-8 text to Base64URL or decode Base64URL back to text."
      onClear={() => setInput("")}
      canClear={Boolean(input)}
    >
      <ModeToggle
        name="base64url-mode"
        value={mode}
        options={[
          { id: "decode", label: "Decode" },
          { id: "encode", label: "Encode" },
        ]}
        onChange={setMode}
      />
      <LabeledTextarea
        label="Input"
        value={input}
        onChange={setInput}
        placeholder={
          mode === "decode"
            ? "eyJhbGciOiJIUzI1NiJ9…"
            : '{"alg":"HS256","typ":"JWT"}'
        }
        rows={4}
      />
      {result && !result.ok && (
        <Alert message={result.message} />
      )}
      {result?.ok && (
        <OutputField label="Output" value={result.output} />
      )}
    </UtilityPanel>
  );
}

function TimestampUtility() {
  const [input, setInput] = useState("1516239022");

  const result = useMemo(() => {
    if (!input.trim()) return null;
    return convertUnixTimestamp(input);
  }, [input]);

  return (
    <UtilityPanel
      title="Unix timestamp"
      description="Convert a Unix timestamp to readable UTC and local time."
      onClear={() => setInput("")}
      canClear={Boolean(input)}
    >
      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium text-zinc-800 dark:text-zinc-200">
          Timestamp
        </span>
        <input
          type="text"
          inputMode="numeric"
          spellCheck={false}
          autoComplete="off"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="1516239022"
          className={INPUT_CLASS.replace("resize-y", "")}
        />
      </label>
      {result && !result.ok && <Alert message={result.message} />}
      {result?.ok && (
        <dl className="grid gap-3 rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm dark:border-zinc-800 dark:bg-zinc-900/40">
          <div>
            <dt className="font-medium text-zinc-700 dark:text-zinc-300">
              Raw value
            </dt>
            <dd className="mt-0.5 font-mono text-zinc-900 dark:text-zinc-100">
              {result.raw}
              <span className="ml-2 text-zinc-500 dark:text-zinc-400">
                ({result.unit})
              </span>
            </dd>
          </div>
          <div>
            <dt className="font-medium text-zinc-700 dark:text-zinc-300">UTC</dt>
            <dd className="mt-0.5 text-zinc-900 dark:text-zinc-100">
              {result.utc}
            </dd>
          </div>
          <div>
            <dt className="font-medium text-zinc-700 dark:text-zinc-300">
              Local
            </dt>
            <dd className="mt-0.5 text-zinc-900 dark:text-zinc-100">
              {result.local}
            </dd>
          </div>
        </dl>
      )}
    </UtilityPanel>
  );
}

function JsonFormatterUtility() {
  const [input, setInput] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [mode, setMode] = useState<JsonFormatMode>("pretty");

  const result = useMemo(() => {
    if (!input.trim()) return null;
    return formatJson(input, mode);
  }, [input, mode]);

  return (
    <UtilityPanel
      title="JSON formatter"
      description="Pretty-print or minify JSON with clear errors for invalid input."
      onClear={() => setInput("")}
      canClear={Boolean(input)}
    >
      <ModeToggle
        name="json-format-mode"
        value={mode}
        options={[
          { id: "pretty", label: "Pretty-print" },
          { id: "minify", label: "Minify" },
        ]}
        onChange={setMode}
      />
      <LabeledTextarea
        label="JSON input"
        value={input}
        onChange={setInput}
        placeholder='{ "keys": [ … ] }'
        rows={8}
      />
      {result && !result.ok && <Alert message={result.message} />}
      {result?.ok && <OutputField label="Formatted JSON" value={result.output} />}
    </UtilityPanel>
  );
}

function KeyInspectorUtility() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<
    Awaited<ReturnType<typeof inspectKeyMaterial>> | null
  >(null);
  const [busy, setBusy] = useState(false);

  const inspect = async () => {
    setBusy(true);
    try {
      const next = await inspectKeyMaterial(input);
      setResult(next);
    } finally {
      setBusy(false);
    }
  };

  return (
    <UtilityPanel
      title="PEM / JWK inspector"
      description="Parse public keys and JWKs. Private key material is rejected or redacted."
      onClear={() => {
        setInput("");
        setResult(null);
      }}
      canClear={Boolean(input) || result !== null}
    >
      <LabeledTextarea
        label="Key material"
        value={input}
        onChange={(value) => {
          setInput(value);
          setResult(null);
        }}
        placeholder={`-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n\nor\n\n{ "kty": "RSA", "n": "…", "e": "AQAB" }`}
        rows={8}
      />
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => void inspect()}
          disabled={busy || !input.trim()}
          className="rounded-md bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
        >
          {busy ? "Inspecting…" : "Inspect key"}
        </button>
      </div>
      {result && !result.ok && <Alert message={result.message} />}
      {result?.ok && (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-zinc-700 dark:text-zinc-300" role="status">
            Format:{" "}
            <span className="font-mono font-medium uppercase">{result.format}</span>
            {" · "}
            {result.entries.length} key{result.entries.length === 1 ? "" : "s"}
          </p>
          {result.entries.map((entry) => (
            <KeyEntryCard key={entry.label} entry={entry} />
          ))}
        </div>
      )}
    </UtilityPanel>
  );
}

function KeyEntryCard({ entry }: { entry: InspectedKeyEntry }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900/40">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
          {entry.label}
        </h3>
        {entry.kty && (
          <span className="rounded-full bg-zinc-100 px-2 py-0.5 font-mono text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
            {entry.kty}
          </span>
        )}
      </div>

      {entry.warnings.length > 0 && (
        <ul className="flex flex-col gap-1 text-sm text-amber-900 dark:text-amber-200">
          {entry.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}

      {entry.fields.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-600 dark:bg-zinc-900/80 dark:text-zinc-400">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">
                  Field
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Value
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {entry.fields.map((field) => (
                <tr key={field.name}>
                  <td className="px-3 py-2 font-mono text-xs">{field.name}</td>
                  <td className="max-w-md truncate px-3 py-2 font-mono text-xs text-zinc-800 dark:text-zinc-200">
                    {field.value}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <OutputField label="Safe JWK JSON" value={entry.safeJson} rows={6} />
    </div>
  );
}

type UtilityPanelProps = {
  title: string;
  description: string;
  onClear: () => void;
  canClear: boolean;
  children: ReactNode;
};

function UtilityPanel({
  title,
  description,
  onClear,
  canClear,
  children,
}: UtilityPanelProps) {
  return (
    <section className="flex flex-col gap-4 rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h3 className="text-base font-medium text-zinc-900 dark:text-zinc-100">
            {title}
          </h3>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            {description}
          </p>
        </div>
        <button
          type="button"
          onClick={onClear}
          disabled={!canClear}
          className="rounded-md border border-zinc-200 bg-white px-3 py-1.5 text-sm font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800"
        >
          Clear
        </button>
      </div>
      {children}
    </section>
  );
}

type ModeToggleProps<T extends string> = {
  name: string;
  value: T;
  options: ReadonlyArray<{ id: T; label: string }>;
  onChange: (value: T) => void;
};

function ModeToggle<T extends string>({
  name,
  value,
  options,
  onChange,
}: ModeToggleProps<T>) {
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="sr-only">Mode</legend>
      <div className="flex flex-wrap gap-1">
        {options.map((option) => {
          const active = value === option.id;
          return (
            <label
              key={option.id}
              className={`cursor-pointer rounded-md px-2.5 py-1 text-xs font-medium transition ${
                active
                  ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                  : "bg-zinc-100 text-zinc-700 hover:bg-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
              }`}
            >
              <input
                type="radio"
                name={name}
                value={option.id}
                checked={active}
                onChange={() => onChange(option.id)}
                className="sr-only"
              />
              {option.label}
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

type LabeledTextareaProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
};

function LabeledTextarea({
  label,
  value,
  onChange,
  placeholder,
  rows = 4,
}: LabeledTextareaProps) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="font-medium text-zinc-800 dark:text-zinc-200">
        {label}
      </span>
      <textarea
        rows={rows}
        spellCheck={false}
        autoComplete="off"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={INPUT_CLASS}
      />
    </label>
  );
}

type OutputFieldProps = {
  label: string;
  value: string;
  rows?: number;
};

function OutputField({ label, value, rows = 4 }: OutputFieldProps) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          {label}
        </span>
        <CopyButton label={label} value={value} />
      </div>
      <textarea
        readOnly
        rows={rows}
        value={value}
        className={OUTPUT_CLASS}
      />
    </div>
  );
}

function Alert({ message }: { message: string }) {
  return (
    <p className="text-sm text-red-800 dark:text-red-300" role="alert">
      {message}
    </p>
  );
}
