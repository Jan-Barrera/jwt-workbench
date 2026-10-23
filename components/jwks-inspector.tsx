"use client";

import { useMemo, useState } from "react";

import {
  confirmNetworkOperation,
  NetworkOperationNotice,
} from "@/components/privacy/network-operation-notice";
import {
  isKidHighlight,
  jwkCompatibility,
  matchKeysByKid,
} from "@/lib/jwks/match";
import { parseJwksText, serializeJwk } from "@/lib/jwks/parse";
import type { JwksKeyEntry } from "@/lib/jwks/types";
import { validateJwksFetchUrl } from "@/lib/jwks/url";

type JwksSourceMode = "paste" | "url";

type JwksInspectorProps = {
  tokenKid: string | null;
  tokenAlg: string | null;
  selectedKeyIndex: number | null;
  onSelectKey: (jwkJson: string, keyIndex: number) => void;
  onClearSelection: () => void;
  onJwksTextChange?: (text: string) => void;
};

export function JwksInspector({
  tokenKid,
  tokenAlg,
  selectedKeyIndex,
  onSelectKey,
  onClearSelection,
  onJwksTextChange,
}: JwksInspectorProps) {
  const [mode, setMode] = useState<JwksSourceMode>("paste");
  const [pasteText, setPasteText] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [fetching, setFetching] = useState(false);
  const [fetchedFromNetwork, setFetchedFromNetwork] = useState(false);

  const parseResult = useMemo(() => {
    if (mode !== "paste" || !pasteText.trim()) return null;
    return parseJwksText(pasteText);
  }, [mode, pasteText]);

  const keys = parseResult?.code === "OK" ? parseResult.keys : null;

  const kidMatch = useMemo(() => {
    if (!keys) return null;
    return matchKeysByKid(keys, tokenKid);
  }, [keys, tokenKid]);

  const loadFromUrl = async () => {
    setFetchError(null);
    const validation = validateJwksFetchUrl(urlInput);
    if (validation.code !== "OK") {
      setFetchError(validation.message);
      return;
    }

    const confirmed = confirmNetworkOperation(
      "The application server will download the JWKS from the URL you entered (HTTPS/HTTP only; private addresses blocked). Your JWT is not included in this request.\n\nContinue?",
    );
    if (!confirmed) {
      return;
    }

    setFetching(true);
    try {
      const response = await fetch("/api/jwks/fetch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: validation.url.toString() }),
      });
      const payload = (await response.json()) as {
        code?: string;
        message?: string;
        jwksText?: string;
      };

      if (!response.ok || payload.code !== "OK" || !payload.jwksText) {
        setFetchError(
          payload.message ?? "Could not fetch JWKS from that URL.",
        );
        return;
      }

      setMode("paste");
      setPasteText(payload.jwksText);
      onJwksTextChange?.(payload.jwksText);
      setFetchedFromNetwork(true);
    } catch {
      setFetchError("Network request failed.");
    } finally {
      setFetching(false);
    }
  };

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white px-3 py-3 dark:border-zinc-800 dark:bg-zinc-900/40">
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
          JWKS inspector
        </h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          Load a JSON Web Key Set to pick a verification key. Your JWT is read
          only from the field above — it is never sent to a JWKS URL.
        </p>
      </div>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          JWKS source
        </legend>
        <div className="flex flex-wrap gap-1">
          {(
            [
              { id: "paste" as const, label: "Paste JSON" },
              { id: "url" as const, label: "Fetch URL" },
            ] as const
          ).map((option) => {
            const active = mode === option.id;
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
                  name="jwks-source"
                  value={option.id}
                  checked={active}
                  onChange={() => {
                    setMode(option.id);
                    setFetchError(null);
                  }}
                  className="sr-only"
                />
                {option.label}
              </label>
            );
          })}
        </div>
      </fieldset>

      {mode === "paste" ? (
        <div className="flex flex-col gap-2">
          {fetchedFromNetwork && (
            <p
              className="text-sm text-amber-900 dark:text-amber-200"
              role="status"
            >
              JWKS was loaded via a server fetch of the URL you provided. The
              JWT was not included in that request.
            </p>
          )}
          {!fetchedFromNetwork && pasteText.trim() && (
            <p
              className="inline-flex items-center gap-2 text-sm font-medium text-emerald-800 dark:text-emerald-300"
              role="status"
            >
              <span
                className="inline-block h-2 w-2 rounded-full bg-emerald-500"
                aria-hidden
              />
              Pasted JWKS is processed locally in your browser
            </p>
          )}
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-zinc-800 dark:text-zinc-200">
              JWKS JSON
            </span>
            <textarea
              rows={5}
              spellCheck={false}
              autoComplete="off"
              value={pasteText}
              onChange={(e) => {
                setPasteText(e.target.value);
                setFetchedFromNetwork(false);
                onClearSelection();
                onJwksTextChange?.(e.target.value);
              }}
              placeholder='{ "keys": [ { "kty": "RSA", "kid": "…", … } ] }'
              className="w-full resize-y rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 shadow-sm outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
            />
          </label>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <NetworkOperationNotice>
            Fetching asks the application server to download the JWKS URL you
            provide. Your JWT stays in the browser and is never sent with this
            request.
          </NetworkOperationNotice>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-zinc-800 dark:text-zinc-200">
              JWKS URL
            </span>
            <input
              type="url"
              spellCheck={false}
              autoComplete="off"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://issuer.example/.well-known/jwks.json"
              className="rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
            />
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void loadFromUrl()}
              disabled={fetching || !urlInput.trim()}
              className="rounded-md bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
            >
              {fetching ? "Fetching…" : "Fetch JWKS"}
            </button>
          </div>
          {fetchError && (
            <p className="text-sm text-red-800 dark:text-red-300" role="alert">
              {fetchError}
            </p>
          )}
        </div>
      )}

      {parseResult && parseResult.code !== "OK" && mode === "paste" && pasteText.trim() && (
        <p className="text-sm text-red-800 dark:text-red-300" role="alert">
          {parseResult.message}
        </p>
      )}

      {keys && kidMatch && (
        <>
          <p className="text-sm text-zinc-700 dark:text-zinc-300" role="status">
            Token kid:{" "}
            <span className="font-mono font-medium">
              {tokenKid ?? "(none in header)"}
            </span>
            {" · "}
            {kidMatch.message}
          </p>

          <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-600 dark:bg-zinc-900/80 dark:text-zinc-400">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Select
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    kid
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    kty
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    use
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    alg
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Match / fit
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                {keys.map((entry) => (
                  <JwksKeyRow
                    key={entry.index}
                    entry={entry}
                    tokenAlg={tokenAlg}
                    highlighted={isKidHighlight(entry.index, kidMatch)}
                    selected={selectedKeyIndex === entry.index}
                    onSelect={() => {
                      onSelectKey(serializeJwk(entry.jwk), entry.index);
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

type JwksKeyRowProps = {
  entry: JwksKeyEntry;
  tokenAlg: string | null;
  highlighted: boolean;
  selected: boolean;
  onSelect: () => void;
};

function JwksKeyRow({
  entry,
  tokenAlg,
  highlighted,
  selected,
  onSelect,
}: JwksKeyRowProps) {
  const compatibility = jwkCompatibility(entry.jwk, tokenAlg);
  const rowClass = highlighted
    ? "bg-sky-50 dark:bg-sky-950/30"
    : "bg-white dark:bg-transparent";

  return (
    <tr className={rowClass}>
      <td className="px-3 py-2">
        <input
          type="radio"
          name="jwks-key-select"
          checked={selected}
          onChange={onSelect}
          aria-label={`Use key ${entry.kid ?? entry.index}`}
        />
      </td>
      <td className="px-3 py-2 font-mono text-xs">
        {entry.kid ?? "—"}
      </td>
      <td className="px-3 py-2 font-mono text-xs">{entry.kty}</td>
      <td className="px-3 py-2 font-mono text-xs">{entry.use ?? "—"}</td>
      <td className="px-3 py-2 font-mono text-xs">{entry.alg ?? "—"}</td>
      <td className="px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300">
        {highlighted && (
          <span className="mr-2 rounded-full bg-sky-200 px-1.5 py-0.5 font-medium text-sky-950 dark:bg-sky-900 dark:text-sky-100">
            kid match
          </span>
        )}
        {compatibility.compatible ? (
          <span className="text-emerald-800 dark:text-emerald-300">
            Compatible with token alg
          </span>
        ) : (
          <span title={compatibility.reasons.join(" ")}>
            Incompatible: {compatibility.reasons[0]}
          </span>
        )}
      </td>
    </tr>
  );
}
