"use client";

import { useEffect, useMemo, useState } from "react";

import { buildJwtDebugReport, type DebugFinding } from "@/lib/jwt/debug";
import { decodeJwt } from "@/lib/jwt/decode";
import {
  jwtHeaderAlgorithm,
  toSignatureVerificationResult,
  verifyJwt,
  type VerifyJwtResult,
  type VerifyKeyFormat,
} from "@/lib/jwt/verify";
import type { ValidationOutcome } from "@/lib/jwt/validate";

import { PrivacyToolbar } from "@/components/privacy/privacy-toolbar";

import { JwtProcessingState } from "./jwt-processing-state";
import { ClaimInspector } from "./claim-inspector";
import { JwksInspector } from "./jwks-inspector";
import { SignatureVerificationForm } from "./signature-verification";

const PLACEHOLDER =
  "Paste a compact JWT (header.payload.signature) or Bearer token…";

export function JwtDebugger() {
  const [input, setInput] = useState("");
  const [expectedIssuer, setExpectedIssuer] = useState("");
  const [expectedAudience, setExpectedAudience] = useState("");
  const [clockToleranceSeconds, setClockToleranceSeconds] = useState("0");
  const [keyMaterial, setKeyMaterial] = useState("");
  const [keyFormat, setKeyFormat] = useState<VerifyKeyFormat>("auto");
  const [jwksText, setJwksText] = useState("");
  const [selectedJwksKeyIndex, setSelectedJwksKeyIndex] = useState<
    number | null
  >(null);
  const [verifyState, setVerifyState] = useState<{
    raw: string;
    keyMaterial: string;
    keyFormat: VerifyKeyFormat;
    result: VerifyJwtResult;
  } | null>(null);

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

  const decodePreview = useMemo(() => {
    const trimmed = input.trim();
    if (!trimmed) return null;
    return decodeJwt(input);
  }, [input]);

  const declaredAlg =
    decodePreview?.ok
      ? jwtHeaderAlgorithm(decodePreview.header)
      : verifyResult?.algorithm ?? null;

  const tokenKid =
    decodePreview?.ok &&
    typeof decodePreview.header === "object" &&
    decodePreview.header !== null &&
    "kid" in decodePreview.header &&
    typeof (decodePreview.header as { kid: unknown }).kid === "string"
      ? (decodePreview.header as { kid: string }).kid
      : null;

  const report = useMemo(() => {
    const trimmed = input.trim();
    if (!trimmed) return null;
    const tolerance = Number.parseInt(clockToleranceSeconds, 10);
    return buildJwtDebugReport(input, {
      expectedIssuer: expectedIssuer.trim() || undefined,
      expectedAudience: expectedAudience.trim() || undefined,
      clockToleranceSeconds: Number.isFinite(tolerance) ? tolerance : 0,
      signature: verifyResult
        ? toSignatureVerificationResult(verifyResult)
        : { status: "not_verified" },
      jwksText: jwksText.trim() || undefined,
      selectedJwksKeyIndex,
    });
  }, [
    input,
    expectedIssuer,
    expectedAudience,
    clockToleranceSeconds,
    verifyResult,
    jwksText,
    selectedJwksKeyIndex,
  ]);

  const hasSensitiveState =
    Boolean(input) ||
    Boolean(keyMaterial) ||
    Boolean(jwksText) ||
    Boolean(expectedIssuer) ||
    Boolean(expectedAudience);

  const clear = () => {
    setInput("");
    setExpectedIssuer("");
    setExpectedAudience("");
    setClockToleranceSeconds("0");
    setKeyMaterial("");
    setKeyFormat("auto");
    setJwksText("");
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
        description="Unified troubleshooting report combining structure, claims, configured checks, JWKS key matching, and signature verification. Decoding alone never implies trust."
        onClear={clear}
        canClear={hasSensitiveState}
      />

      <div className="flex flex-col gap-2">
        <label
          htmlFor="jwt-debugger-input"
          className="text-sm font-medium text-zinc-800 dark:text-zinc-200"
        >
          JWT
        </label>
        <textarea
          id="jwt-debugger-input"
          name="jwt"
          rows={4}
          spellCheck={false}
          autoComplete="off"
          placeholder={PLACEHOLDER}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="w-full resize-y rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 shadow-sm outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
        />
        {report && !report.decode.ok && (
          <p
            className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200"
            role="alert"
          >
            {report.decode.error}
          </p>
        )}
      </div>

      {report && (
        <>
          <JwtProcessingState
            decoded={report.decode.ok}
            validationChecks={report.validation.checks}
            verifyResult={verifyResult}
          />

          <section
            className="flex flex-col gap-3"
            aria-labelledby="debugger-config-heading"
          >
            <div className="flex flex-col gap-1">
              <h2
                id="debugger-config-heading"
                className="text-sm font-semibold text-zinc-800 dark:text-zinc-200"
              >
                Validation configuration
              </h2>
              <p className="text-sm text-zinc-600 dark:text-zinc-400">
                Optional expected claims and clock skew. Unconfigured checks stay
                neutral.
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
          </section>

          <JwksInspector
            tokenKid={tokenKid}
            tokenAlg={declaredAlg}
            selectedKeyIndex={selectedJwksKeyIndex}
            onSelectKey={applyJwksKey}
            onClearSelection={() => setSelectedJwksKeyIndex(null)}
            onJwksTextChange={setJwksText}
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

          <DebugReportPanel report={report} />
        </>
      )}
    </div>
  );
}

type DebugReportPanelProps = {
  report: NonNullable<ReturnType<typeof buildJwtDebugReport>>;
};

function DebugReportPanel({ report }: DebugReportPanelProps) {
  const validationFindings = report.findings.filter(
    (f) =>
      !f.id.startsWith("observation.") &&
      !f.id.startsWith("header.") &&
      !f.id.startsWith("key_matching."),
  );

  const headerFindings = report.findings.filter((f) =>
    f.id.startsWith("header."),
  );

  const keyFindings = report.findings.filter((f) =>
    f.id.startsWith("key_matching."),
  );

  return (
    <section
      className="flex flex-col gap-6 rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900/40"
      aria-labelledby="debug-report-heading"
    >
      <div className="flex flex-col gap-2">
        <h2
          id="debug-report-heading"
          className="text-base font-semibold text-zinc-900 dark:text-zinc-100"
        >
          Diagnostic report
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <SummaryBadge
            label="Structure"
            outcome={
              report.decode.ok
                ? report.failures.some((f) => f.id === "structure")
                  ? "fail"
                  : "pass"
                : "fail"
            }
          />
          {report.algorithm && (
            <span className="rounded-full bg-zinc-100 px-2.5 py-0.5 font-mono text-xs text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
              alg {report.algorithm}
            </span>
          )}
          {report.kid && (
            <span className="rounded-full bg-zinc-100 px-2.5 py-0.5 font-mono text-xs text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
              kid {report.kid}
            </span>
          )}
        </div>
      </div>

      {report.failures.length > 0 && (
        <FindingGroup
          title="Validation failures"
          description="These checks failed and may explain authorization errors."
          findings={report.failures}
          tone="failure"
        />
      )}

      <FindingGroup
        title="Validation checks"
        description="Independent structure, temporal, configured, and signature checks with evidence."
        findings={validationFindings}
        tone="neutral"
      />

      {headerFindings.length > 0 && (
        <FindingGroup
          title="Header metadata"
          description="Algorithm and key identifier declared in the token header."
          findings={headerFindings}
          tone="neutral"
        />
      )}

      {report.keyMatching && (
        <FindingGroup
          title="JWKS key matching"
          description={
            report.keyMatching.parseError
              ? "JWKS could not be parsed."
              : report.keyMatching.kidMatch
                ? report.keyMatching.kidMatch.message
                : "JWKS supplied."
          }
          findings={
            keyFindings.length > 0
              ? keyFindings
              : [
                  {
                    id: "key_matching.neutral",
                    category: "key_matching",
                    label: "JWKS key matching",
                    outcome: "info",
                    severity: "info",
                    message: "No kid match findings for the supplied JWKS.",
                  },
                ]
          }
          tone="neutral"
        />
      )}

      {report.claims.length > 0 && (
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
              Recognized claims
            </h3>
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              Payload claims with temporal status where applicable. Missing
              optional claims are not treated as failures.
            </p>
          </div>
          <ClaimInspector payload={report.decode.ok ? report.decode.payload : {}} />
        </div>
      )}

      {report.observations.length > 0 && (
        <FindingGroup
          title="Advisory observations"
          description="Security and informational notes separate from validation failures."
          findings={report.observations}
          tone="advisory"
        />
      )}
    </section>
  );
}

type FindingGroupProps = {
  title: string;
  description: string;
  findings: DebugFinding[];
  tone: "failure" | "neutral" | "advisory";
};

function FindingGroup({
  title,
  description,
  findings,
  tone,
}: FindingGroupProps) {
  const borderClass =
    tone === "failure"
      ? "border-red-200 dark:border-red-900/40"
      : tone === "advisory"
        ? "border-amber-200 dark:border-amber-900/40"
        : "border-zinc-200 dark:border-zinc-800";

  return (
    <div className={`flex flex-col gap-3 rounded-lg border ${borderClass} p-3`}>
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
          {title}
        </h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">{description}</p>
      </div>
      <ul className="flex flex-col gap-2">
        {findings.map((finding) => (
          <FindingRow key={finding.id} finding={finding} />
        ))}
      </ul>
    </div>
  );
}

function FindingRow({ finding }: { finding: DebugFinding }) {
  return (
    <li className="rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-3 dark:border-zinc-800 dark:bg-zinc-950/50">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <span className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
          {finding.label}
        </span>
        <OutcomeBadge outcome={finding.outcome} />
      </div>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
        {finding.message}
      </p>
      {(finding.expected !== undefined || finding.actual !== undefined) && (
        <dl className="mt-2 grid gap-1 text-xs text-zinc-600 dark:text-zinc-400 sm:grid-cols-2">
          {finding.expected !== undefined && (
            <div>
              <dt className="font-medium text-zinc-700 dark:text-zinc-300">
                Expected
              </dt>
              <dd className="font-mono break-all">{finding.expected}</dd>
            </div>
          )}
          {finding.actual !== undefined && (
            <div>
              <dt className="font-medium text-zinc-700 dark:text-zinc-300">
                Received
              </dt>
              <dd className="font-mono break-all">{finding.actual}</dd>
            </div>
          )}
        </dl>
      )}
    </li>
  );
}

function SummaryBadge({
  label,
  outcome,
}: {
  label: string;
  outcome: ValidationOutcome;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className="font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
      <OutcomeBadge outcome={outcome} />
    </span>
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
