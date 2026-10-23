"use client";

import { useCallback, useMemo, useState } from "react";

import { decodeJwt } from "@/lib/jwt/decode";
import {
  SUPPORTED_ALGORITHMS,
  buildHeaderObject,
  buildPayloadFromFields,
  createLocalSigningMaterial,
  generateJwt,
  parseJsonObject,
  type PayloadFieldInput,
  type SignKeyFormat,
  type SupportedAlgorithm,
} from "@/lib/jwt/generate";
import { isHmacAlgorithm } from "@/lib/jwt/verify";

import { PrivacyToolbar } from "@/components/privacy/privacy-toolbar";

import { ClaimInspector } from "./claim-inspector";
import { CopyButton } from "./copy-button";
import { JsonHighlight } from "./json-highlight";

type EditorMode = "fields" | "json";

const INPUT_CLASS =
  "rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100";

const DEFAULT_HEADER_JSON = '{\n  "alg": "HS256",\n  "typ": "JWT"\n}';

const DEFAULT_PAYLOAD_JSON = '{\n  "sub": "developer"\n}';

function defaultTimestamps(now = new Date()) {
  const iat = Math.floor(now.getTime() / 1000);
  return {
    iat: String(iat),
    exp: String(iat + 3600),
  };
}

export function JwtGenerator() {
  const [algorithm, setAlgorithm] = useState<SupportedAlgorithm>("HS256");
  const [headerMode, setHeaderMode] = useState<EditorMode>("fields");
  const [headerTyp, setHeaderTyp] = useState("JWT");
  const [headerKid, setHeaderKid] = useState("");
  const [headerJson, setHeaderJson] = useState(DEFAULT_HEADER_JSON);

  const [payloadMode, setPayloadMode] = useState<EditorMode>("fields");
  const [payloadFields, setPayloadFields] = useState<PayloadFieldInput>(() => ({
    sub: "developer",
    ...defaultTimestamps(),
    customClaims: [],
  }));
  const [payloadJson, setPayloadJson] = useState(DEFAULT_PAYLOAD_JSON);

  const [keyMaterial, setKeyMaterial] = useState("");
  const [keyFormat, setKeyFormat] = useState<SignKeyFormat>("auto");
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [keyGenMessage, setKeyGenMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const decoded = useMemo(() => {
    if (!generatedToken) return null;
    return decodeJwt(generatedToken);
  }, [generatedToken]);

  const syncAlgorithmInHeaderJson = useCallback(
    (nextAlg: SupportedAlgorithm) => {
      setHeaderJson((current) => {
        try {
          const parsed = JSON.parse(current) as Record<string, unknown>;
          parsed.alg = nextAlg === "Ed25519" ? "EdDSA" : nextAlg;
          return JSON.stringify(parsed, null, 2);
        } catch {
          return buildHeaderJsonTemplate(nextAlg);
        }
      });
    },
    [],
  );

  const onAlgorithmChange = (next: SupportedAlgorithm) => {
    setAlgorithm(next);
    syncAlgorithmInHeaderJson(next);
    setGeneratedToken(null);
    setError(null);
  };

  const addCustomClaim = () => {
    setPayloadFields((prev) => ({
      ...prev,
      customClaims: [...(prev.customClaims ?? []), { name: "", value: "" }],
    }));
  };

  const updateCustomClaim = (
    index: number,
    patch: Partial<{ name: string; value: string }>,
  ) => {
    setPayloadFields((prev) => {
      const list = [...(prev.customClaims ?? [])];
      list[index] = { ...list[index], ...patch };
      return { ...prev, customClaims: list };
    });
  };

  const removeCustomClaim = (index: number) => {
    setPayloadFields((prev) => ({
      ...prev,
      customClaims: (prev.customClaims ?? []).filter((_, i) => i !== index),
    }));
  };

  const generateKeys = async () => {
    setBusy(true);
    setKeyGenMessage(null);
    setError(null);
    const result = await createLocalSigningMaterial(algorithm);
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setKeyMaterial(result.privateKeyMaterial);
    setKeyFormat(isHmacAlgorithm(algorithm) ? "secret" : "pem");
    setKeyGenMessage(result.message);
    if (!isHmacAlgorithm(algorithm)) {
      setKeyGenMessage(
        `${result.message} Public key copied below for verification.`,
      );
    }
  };

  const sign = async () => {
    setError(null);
    setGeneratedToken(null);

    let header: Record<string, unknown>;
    if (headerMode === "json") {
      const parsed = parseJsonObject(headerJson, "Header");
      if (!parsed.ok) {
        setError(parsed.message);
        return;
      }
      header = parsed.value;
    } else {
      header = buildHeaderObject(algorithm, {
        typ: headerTyp,
        kid: headerKid,
      });
    }

    let payload: Record<string, unknown>;
    if (payloadMode === "json") {
      const parsed = parseJsonObject(payloadJson, "Payload");
      if (!parsed.ok) {
        setError(parsed.message);
        return;
      }
      payload = parsed.value;
    } else {
      const built = buildPayloadFromFields(payloadFields);
      if (!built.ok) {
        setError(built.message);
        return;
      }
      payload = built.payload;
    }

    setBusy(true);
    const result = await generateJwt({
      algorithm,
      header,
      payload,
      keyMaterial,
      keyFormat,
    });
    setBusy(false);

    if (!result.ok) {
      setError(result.message);
      return;
    }
    setGeneratedToken(result.token);
  };

  const clear = () => {
    setGeneratedToken(null);
    setError(null);
    setKeyGenMessage(null);
    setKeyMaterial("");
    setKeyFormat("auto");
  };

  const hasState = Boolean(generatedToken || keyMaterial || error);

  return (
    <div className="flex w-full flex-col gap-8">
      <PrivacyToolbar
        variant="development"
        description="Build header and payload claims, choose a supported algorithm, and sign with a secret or private key in this browser. The result is decoded below for immediate inspection."
        onClear={clear}
        canClear={hasState}
        clearLabel="Clear secrets & output"
      />

      <section className="flex flex-col gap-3" aria-labelledby="gen-alg-heading">
        <h2
          id="gen-alg-heading"
          className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
        >
          Signing algorithm
        </h2>
        <select
          value={algorithm}
          onChange={(e) =>
            onAlgorithmChange(e.target.value as SupportedAlgorithm)
          }
          className={`max-w-md ${INPUT_CLASS}`}
        >
          {SUPPORTED_ALGORITHMS.map((alg) => (
            <option key={alg} value={alg}>
              {alg}
            </option>
          ))}
        </select>
      </section>

      <section className="flex flex-col gap-3" aria-labelledby="gen-header-heading">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2
            id="gen-header-heading"
            className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
          >
            Header
          </h2>
          <ModeToggle mode={headerMode} onChange={setHeaderMode} />
        </div>
        {headerMode === "fields" ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-zinc-800 dark:text-zinc-200">
                typ
              </span>
              <input
                type="text"
                value={headerTyp}
                onChange={(e) => setHeaderTyp(e.target.value)}
                className={INPUT_CLASS}
                spellCheck={false}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-zinc-800 dark:text-zinc-200">
                kid (optional)
              </span>
              <input
                type="text"
                value={headerKid}
                onChange={(e) => setHeaderKid(e.target.value)}
                className={INPUT_CLASS}
                spellCheck={false}
              />
            </label>
          </div>
        ) : (
          <textarea
            rows={5}
            spellCheck={false}
            value={headerJson}
            onChange={(e) => setHeaderJson(e.target.value)}
            className={`w-full resize-y ${INPUT_CLASS}`}
            aria-label="Header JSON"
          />
        )}
      </section>

      <section className="flex flex-col gap-3" aria-labelledby="gen-payload-heading">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2
            id="gen-payload-heading"
            className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
          >
            Payload
          </h2>
          <ModeToggle mode={payloadMode} onChange={setPayloadMode} />
        </div>
        {payloadMode === "fields" ? (
          <div className="flex flex-col gap-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <ClaimField
                label="iss (issuer)"
                value={payloadFields.iss ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, iss: v }))
                }
              />
              <ClaimField
                label="sub (subject)"
                value={payloadFields.sub ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, sub: v }))
                }
              />
              <ClaimField
                label="aud (audience)"
                value={payloadFields.aud ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, aud: v }))
                }
                hint="Comma-separated for multiple audiences"
              />
              <ClaimField
                label="jti"
                value={payloadFields.jti ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, jti: v }))
                }
              />
              <ClaimField
                label="iat (issued at, Unix s)"
                value={payloadFields.iat ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, iat: v }))
                }
              />
              <ClaimField
                label="nbf (not before, Unix s)"
                value={payloadFields.nbf ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, nbf: v }))
                }
              />
              <ClaimField
                label="exp (expiration, Unix s)"
                value={payloadFields.exp ?? ""}
                onChange={(v) =>
                  setPayloadFields((p) => ({ ...p, exp: v }))
                }
              />
            </div>
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
                  Custom claims
                </h3>
                <button
                  type="button"
                  onClick={addCustomClaim}
                  className="rounded-md border border-zinc-200 px-2.5 py-1 text-xs font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-200 dark:hover:bg-zinc-800"
                >
                  Add claim
                </button>
              </div>
              {(payloadFields.customClaims ?? []).length === 0 ? (
                <p className="text-sm text-zinc-500 dark:text-zinc-400">
                  No custom claims. Values are parsed as JSON when valid.
                </p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {(payloadFields.customClaims ?? []).map((claim, index) => (
                    <li
                      key={index}
                      className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]"
                    >
                      <input
                        type="text"
                        placeholder="name"
                        value={claim.name}
                        onChange={(e) =>
                          updateCustomClaim(index, { name: e.target.value })
                        }
                        className={INPUT_CLASS}
                        spellCheck={false}
                      />
                      <input
                        type="text"
                        placeholder='value or JSON e.g. "admin"'
                        value={claim.value}
                        onChange={(e) =>
                          updateCustomClaim(index, { value: e.target.value })
                        }
                        className={INPUT_CLASS}
                        spellCheck={false}
                      />
                      <button
                        type="button"
                        onClick={() => removeCustomClaim(index)}
                        className="rounded-md border border-red-200 px-2 py-1 text-xs font-medium text-red-800 hover:bg-red-50 dark:border-red-900/50 dark:text-red-200 dark:hover:bg-red-950/40"
                      >
                        Remove
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : (
          <textarea
            rows={8}
            spellCheck={false}
            value={payloadJson}
            onChange={(e) => setPayloadJson(e.target.value)}
            className={`w-full resize-y ${INPUT_CLASS}`}
            aria-label="Payload JSON"
          />
        )}
      </section>

      <section className="flex flex-col gap-3" aria-labelledby="gen-key-heading">
        <h2
          id="gen-key-heading"
          className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
        >
          Signing key
        </h2>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {isHmacAlgorithm(algorithm)
            ? "Shared secret for HMAC. Stays in this browser."
            : "Private key (PKCS#8 PEM or private JWK). Never sent to the server."}
        </p>
        <fieldset className="flex flex-col gap-2">
          <legend className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
            Key format
          </legend>
          <div className="flex flex-wrap gap-1">
            {SIGN_KEY_FORMATS.map((option) => {
              const active = keyFormat === option.value;
              return (
                <label
                  key={option.value}
                  className={`cursor-pointer rounded-md px-2.5 py-1 text-xs font-medium transition ${
                    active
                      ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                      : "bg-zinc-100 text-zinc-700 hover:bg-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
                  }`}
                >
                  <input
                    type="radio"
                    name="sign-key-format"
                    value={option.value}
                    checked={active}
                    onChange={() => setKeyFormat(option.value)}
                    className="sr-only"
                  />
                  {option.label}
                </label>
              );
            })}
          </div>
        </fieldset>
        <textarea
          rows={4}
          spellCheck={false}
          autoComplete="off"
          value={keyMaterial}
          onChange={(e) => setKeyMaterial(e.target.value)}
          placeholder={signKeyPlaceholder(algorithm, keyFormat)}
          className={`w-full resize-y ${INPUT_CLASS}`}
        />
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={generateKeys}
            disabled={busy}
            className="rounded-md border border-zinc-200 bg-white px-3 py-1.5 text-sm font-medium text-zinc-800 hover:bg-zinc-50 disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
          >
            Generate key material locally
          </button>
          <button
            type="button"
            onClick={sign}
            disabled={busy}
            className="rounded-md bg-zinc-900 px-4 py-1.5 text-sm font-semibold text-white hover:bg-zinc-800 disabled:opacity-40 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            {busy ? "Signing…" : "Sign JWT"}
          </button>
        </div>
        {keyGenMessage && (
          <p className="text-sm text-emerald-800 dark:text-emerald-300">
            {keyGenMessage}
          </p>
        )}
        {error && (
          <p
            className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200"
            role="alert"
          >
            {error}
          </p>
        )}
      </section>

      {generatedToken && decoded?.ok && (
        <section className="flex flex-col gap-4" aria-labelledby="gen-output-heading">
          <div className="flex flex-wrap items-center gap-2">
            <h2
              id="gen-output-heading"
              className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
            >
              Generated token
            </h2>
            <span className="rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide text-amber-950 dark:bg-amber-950 dark:text-amber-100">
              Test artifact
            </span>
            <CopyButton label="generated JWT" value={generatedToken} />
          </div>
          <p
            className="break-all rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 font-mono text-sm text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900/50 dark:text-zinc-200"
          >
            {generatedToken}
          </p>

          <div className="grid gap-6 lg:grid-cols-2">
            <JsonPanel title="Decoded header" json={decoded.headerJson} />
            <JsonPanel title="Decoded payload" json={decoded.payloadJson} />
          </div>

          <div className="flex flex-col gap-3">
            <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
              Claim inspector
            </h3>
            <ClaimInspector payload={decoded.payload} />
          </div>
        </section>
      )}
    </div>
  );
}

const SIGN_KEY_FORMATS: { value: SignKeyFormat; label: string }[] = [
  { value: "auto", label: "Auto" },
  { value: "secret", label: "Shared secret" },
  { value: "pem", label: "Private key (PEM)" },
  { value: "jwk", label: "JWK" },
];

function signKeyPlaceholder(
  algorithm: SupportedAlgorithm,
  format: SignKeyFormat,
): string {
  if (isHmacAlgorithm(algorithm)) {
    return "Paste HMAC secret or generate one locally";
  }
  if (format === "jwk") {
    return "Paste a private JWK JSON object";
  }
  return "Paste a PKCS#8 private key (BEGIN PRIVATE KEY)";
}

function buildHeaderJsonTemplate(algorithm: SupportedAlgorithm): string {
  return JSON.stringify(
    {
      alg: algorithm === "Ed25519" ? "EdDSA" : algorithm,
      typ: "JWT",
    },
    null,
    2,
  );
}

type ModeToggleProps = {
  mode: EditorMode;
  onChange: (mode: EditorMode) => void;
};

function ModeToggle({ mode, onChange }: ModeToggleProps) {
  return (
    <div className="flex rounded-md border border-zinc-200 p-0.5 dark:border-zinc-700">
      {(
        [
          { value: "fields" as const, label: "Fields" },
          { value: "json" as const, label: "JSON" },
        ] as const
      ).map((option) => {
        const active = mode === option.value;
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              active
                ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

type ClaimFieldProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
};

function ClaimField({ label, value, onChange, hint }: ClaimFieldProps) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="font-medium text-zinc-800 dark:text-zinc-200">
        {label}
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={INPUT_CLASS}
        spellCheck={false}
      />
      {hint ? (
        <span className="text-xs text-zinc-500 dark:text-zinc-400">{hint}</span>
      ) : null}
    </label>
  );
}

type JsonPanelProps = {
  title: string;
  json: string;
};

function JsonPanel({ title, json }: JsonPanelProps) {
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
          {title}
        </h3>
        <CopyButton label={title} value={json} />
      </div>
      <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/50">
        <JsonHighlight json={json} />
      </div>
    </section>
  );
}
