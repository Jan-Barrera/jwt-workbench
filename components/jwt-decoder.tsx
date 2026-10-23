"use client";

import { useEffect, useMemo, useState } from "react";

import { decodeJwt } from "@/lib/jwt/decode";
import { validateJwt } from "@/lib/jwt/validate";
import {
  jwtHeaderAlgorithm,
  toSignatureVerificationResult,
  verifyJwt,
  type VerifyJwtResult,
  type VerifyKeyFormat,
} from "@/lib/jwt/verify";

import { PrivacyToolbar } from "@/components/privacy/privacy-toolbar";

import { JwtProcessingState } from "./jwt-processing-state";
import { ClaimInspector } from "./claim-inspector";
import { CopyButton } from "./copy-button";
import { JsonHighlight } from "./json-highlight";
import { JwtValidationPanel } from "./jwt-validation-panel";
import { JwksInspector } from "./jwks-inspector";
import { SignatureVerificationForm } from "./signature-verification";

const SAMPLE_PLACEHOLDER =
  "Paste a compact JWT (header.payload.signature) or Bearer token…";

export function JwtDecoder() {
  const [input, setInput] = useState("");
  const [expectedIssuer, setExpectedIssuer] = useState("");
  const [expectedAudience, setExpectedAudience] = useState("");
  const [clockToleranceSeconds, setClockToleranceSeconds] = useState("0");
  const [keyMaterial, setKeyMaterial] = useState("");
  const [keyFormat, setKeyFormat] = useState<VerifyKeyFormat>("auto");
  const [selectedJwksKeyIndex, setSelectedJwksKeyIndex] = useState<
    number | null
  >(null);
  const [verifyState, setVerifyState] = useState<{
    raw: string;
    keyMaterial: string;
    keyFormat: VerifyKeyFormat;
    result: VerifyJwtResult;
  } | null>(null);

  const result = useMemo(() => {
    const trimmed = input.trim();
    if (!trimmed) return null;
    return decodeJwt(input);
  }, [input]);

  useEffect(() => {
    if (!input.trim()) {
      return;
    }

    let cancelled = false;
    const raw = input;
    const material = keyMaterial;
    const format = keyFormat;
    void verifyJwt(raw, { keyMaterial: material, keyFormat: format }).then(
      (next) => {
        if (!cancelled) {
          setVerifyState({
            raw,
            keyMaterial: material,
            keyFormat: format,
            result: next,
          });
        }
      },
    );

    return () => {
      cancelled = true;
    };
  }, [input, keyMaterial, keyFormat]);

  const verifyResult =
    input.trim() &&
    verifyState &&
    verifyState.raw === input &&
    verifyState.keyMaterial === keyMaterial &&
    verifyState.keyFormat === keyFormat
      ? verifyState.result
      : null;

  const validation = useMemo(() => {
    const trimmed = input.trim();
    if (!trimmed) return null;
    const tolerance = Number.parseInt(clockToleranceSeconds, 10);
    return validateJwt(input, {
      expectedIssuer: expectedIssuer.trim() || undefined,
      expectedAudience: expectedAudience.trim() || undefined,
      clockToleranceSeconds: Number.isFinite(tolerance) ? tolerance : 0,
      signature: verifyResult
        ? toSignatureVerificationResult(verifyResult)
        : { status: "not_verified" },
    });
  }, [
    input,
    expectedIssuer,
    expectedAudience,
    clockToleranceSeconds,
    verifyResult,
  ]);

  const declaredAlg =
    result?.ok ? jwtHeaderAlgorithm(result.header) : verifyResult?.algorithm ?? null;

  const tokenKid =
    result?.ok &&
    typeof result.header === "object" &&
    result.header !== null &&
    "kid" in result.header &&
    typeof (result.header as { kid: unknown }).kid === "string"
      ? (result.header as { kid: string }).kid
      : null;

  const hasSensitiveState =
    Boolean(input) ||
    Boolean(keyMaterial) ||
    Boolean(expectedIssuer) ||
    Boolean(expectedAudience);

  const clear = () => {
    setInput("");
    setExpectedIssuer("");
    setExpectedAudience("");
    setClockToleranceSeconds("0");
    setKeyMaterial("");
    setKeyFormat("auto");
    setSelectedJwksKeyIndex(null);
    setVerifyState(null);
  };

  const applyJwksKey = (jwkJson: string, keyIndex: number) => {
    setKeyMaterial(jwkJson);
    setKeyFormat("jwk");
    setSelectedJwksKeyIndex(keyIndex);
  };

  return (
    <div className="flex w-full flex-col gap-8">
      <PrivacyToolbar
        description="Decoding shows header and payload JSON. Signature verification is a separate cryptographic check and never runs unless you supply a key."
        onClear={clear}
        canClear={hasSensitiveState}
      />

      <div className="flex flex-col gap-2">
        <label htmlFor="jwt-input" className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          JWT
        </label>
        <textarea
          id="jwt-input"
          name="jwt"
          rows={4}
          spellCheck={false}
          autoComplete="off"
          placeholder={SAMPLE_PLACEHOLDER}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="w-full resize-y rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 shadow-sm outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
        />
        {result && !result.ok && (
          <p
            className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200"
            role="alert"
          >
            {result.error}
          </p>
        )}
      </div>

      {(result?.ok || validation) && (
        <JwtProcessingState
          decoded={Boolean(result?.ok)}
          validationChecks={validation?.checks ?? null}
          verifyResult={verifyResult}
        />
      )}

      {validation && (
        <section
          className="flex flex-col gap-3"
          aria-labelledby="validation-heading"
        >
          <div className="flex flex-col gap-1">
            <h2
              id="validation-heading"
              className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
            >
              JWT validation
            </h2>
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              Each check runs independently. Configure expected claims and clock
              skew. Signature status is not verified until you supply key
              material below.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-zinc-800 dark:text-zinc-200">
                Expected issuer (iss)
              </span>
              <input
                type="text"
                value={expectedIssuer}
                onChange={(e) => setExpectedIssuer(e.target.value)}
                placeholder="https://issuer.example"
                spellCheck={false}
                autoComplete="off"
                className="rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-zinc-800 dark:text-zinc-200">
                Expected audience (aud)
              </span>
              <input
                type="text"
                value={expectedAudience}
                onChange={(e) => setExpectedAudience(e.target.value)}
                placeholder="orders-api"
                spellCheck={false}
                autoComplete="off"
                className="rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-zinc-800 dark:text-zinc-200">
                Clock tolerance (seconds)
              </span>
              <input
                type="number"
                min={0}
                step={1}
                value={clockToleranceSeconds}
                onChange={(e) => setClockToleranceSeconds(e.target.value)}
                className="rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
              />
            </label>
          </div>

          <JwksInspector
            tokenKid={tokenKid}
            tokenAlg={declaredAlg}
            selectedKeyIndex={selectedJwksKeyIndex}
            onSelectKey={applyJwksKey}
            onClearSelection={() => setSelectedJwksKeyIndex(null)}
          />

          <SignatureVerificationForm
            algorithm={declaredAlg}
            keyMaterial={keyMaterial}
            keyFormat={keyFormat}
            onKeyMaterialChange={(value) => {
              setKeyMaterial(value);
              setSelectedJwksKeyIndex(null);
            }}
            onKeyFormatChange={(value) => {
              setKeyFormat(value);
              setSelectedJwksKeyIndex(null);
            }}
            result={verifyResult}
          />

          <JwtValidationPanel checks={validation.checks} />
        </section>
      )}

      {result?.ok && (
        <>
          <section className="flex flex-col gap-2" aria-labelledby="segments-heading">
            <div className="flex items-center justify-between gap-2">
              <h2
                id="segments-heading"
                className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
              >
                Encoded segments
              </h2>
              <CopyButton label="full JWT" value={result.normalizedToken} />
            </div>
            <p className="break-all font-mono text-sm leading-relaxed">
              <span className="rounded bg-amber-100/80 px-0.5 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100">
                {result.segments.header}
              </span>
              <span className="text-zinc-400">.</span>
              <span className="rounded bg-sky-100/80 px-0.5 text-sky-950 dark:bg-sky-950/50 dark:text-sky-100">
                {result.segments.payload}
              </span>
              <span className="text-zinc-400">.</span>
              <span className="rounded bg-violet-100/80 px-0.5 text-violet-950 dark:bg-violet-950/50 dark:text-violet-100">
                {result.segments.signature}
              </span>
            </p>
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <DecodedPanel title="Header" json={result.headerJson} />
            <DecodedPanel title="Payload" json={result.payloadJson} />
          </div>

          <section
            className="flex flex-col gap-3"
            aria-labelledby="claims-heading"
          >
            <h2
              id="claims-heading"
              className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
            >
              Claim inspector
            </h2>
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              Registered and custom payload claims with human-readable
              interpretations. Times use your browser locale; status uses the
              current clock.
            </p>
            <ClaimInspector payload={result.payload} />
          </section>

          <section className="flex flex-col gap-2" aria-labelledby="signature-heading">
            <div className="flex items-center justify-between gap-2">
              <h2
                id="signature-heading"
                className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
              >
                Encoded signature
              </h2>
              <CopyButton label="encoded signature" value={result.segments.signature} />
            </div>
            <p
              className="break-all rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 font-mono text-sm text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900/50 dark:text-zinc-200"
            >
              {result.segments.signature}
            </p>
          </section>
        </>
      )}
    </div>
  );
}

type DecodedPanelProps = {
  title: string;
  json: string;
};

function DecodedPanel({ title, json }: DecodedPanelProps) {
  return (
    <section className="flex flex-col gap-2" aria-labelledby={`${title}-heading`}>
      <div className="flex items-center justify-between gap-2">
        <h2
          id={`${title}-heading`}
          className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
        >
          {title}
        </h2>
        <CopyButton label={title} value={json} />
      </div>
      <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/50">
        <JsonHighlight json={json} />
      </div>
    </section>
  );
}
