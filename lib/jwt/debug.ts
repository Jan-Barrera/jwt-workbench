import { inspectPayloadClaims, type InspectedClaim } from "./claims";
import { decodeJwt, type JwtDecodeResult } from "./decode";
import { jwkCompatibility, matchKeysByKid } from "@/lib/jwks/match";
import { parseJwksText } from "@/lib/jwks/parse";
import type { JwksKeyEntry, KidMatchResult } from "@/lib/jwks/types";
import {
  validateJwt,
  type SignatureVerificationResult,
  type ValidateJwtResult,
  type ValidationCheck,
  type ValidationOutcome,
  type ValidationSeverity,
} from "./validate";
import {
  isSupportedAlgorithm,
  jwtHeaderAlgorithm,
} from "./verify";

export type DebugFindingCategory =
  | "structure"
  | "claims"
  | "configured"
  | "header"
  | "key_matching"
  | "signature";

export type DebugFinding = {
  id: string;
  category: DebugFindingCategory;
  label: string;
  outcome: ValidationOutcome;
  severity: ValidationSeverity;
  message: string;
  expected?: string;
  actual?: string;
};

export type KeyMatchingReport = {
  supplied: true;
  parseError: string | null;
  keys: JwksKeyEntry[] | null;
  kidMatch: KidMatchResult | null;
  selectedKeyIndex: number | null;
  selectedKeyCompatible: boolean | null;
  selectedKeyReasons: string[];
};

export type DebugJwtOptions = {
  expectedIssuer?: string;
  expectedAudience?: string;
  clockToleranceSeconds?: number;
  signature?: SignatureVerificationResult;
  jwksText?: string;
  selectedJwksKeyIndex?: number | null;
  now?: Date;
};

export type JwtDebugReport = {
  decode: JwtDecodeResult;
  algorithm: string | null;
  kid: string | null;
  validation: ValidateJwtResult;
  claims: InspectedClaim[];
  keyMatching: KeyMatchingReport | null;
  findings: DebugFinding[];
  failures: DebugFinding[];
  observations: DebugFinding[];
};

function mapCheckCategory(id: ValidationCheck["id"]): DebugFindingCategory {
  switch (id) {
    case "structure":
      return "structure";
    case "expiration":
    case "not_before":
      return "claims";
    case "issuer":
    case "audience":
      return "configured";
    case "signature":
      return "signature";
  }
}

function checkToFinding(check: ValidationCheck): DebugFinding {
  return {
    id: check.id,
    category: mapCheckCategory(check.id),
    label: check.label,
    outcome: check.outcome,
    severity: check.severity,
    message: check.message,
    expected: check.expected,
    actual: check.actual,
  };
}

function extractKid(header: unknown): string | null {
  if (
    typeof header === "object" &&
    header !== null &&
    "kid" in header &&
    typeof (header as { kid: unknown }).kid === "string"
  ) {
    return (header as { kid: string }).kid;
  }
  return null;
}

function headerFindings(
  decode: JwtDecodeResult,
  algorithm: string | null,
  kid: string | null,
): DebugFinding[] {
  if (!decode.ok) {
    return [];
  }

  const findings: DebugFinding[] = [];

  if (algorithm) {
    findings.push({
      id: "header.alg",
      category: "header",
      label: "Signing algorithm",
      outcome: "info",
      severity: "info",
      message: `Token header declares alg ${algorithm}.`,
      actual: algorithm,
    });
  } else {
    findings.push({
      id: "header.alg",
      category: "header",
      label: "Signing algorithm",
      outcome: "warning",
      severity: "warning",
      message: "Token header has no alg claim.",
    });
  }

  if (kid) {
    findings.push({
      id: "header.kid",
      category: "header",
      label: "Key ID",
      outcome: "info",
      severity: "info",
      message: `Token header declares kid "${kid}".`,
      actual: kid,
    });
  } else {
    findings.push({
      id: "header.kid",
      category: "header",
      label: "Key ID",
      outcome: "info",
      severity: "info",
      message: "Token header has no kid. Key selection from JWKS requires an explicit pick.",
    });
  }

  return findings;
}

function securityObservations(
  decode: JwtDecodeResult,
  algorithm: string | null,
): DebugFinding[] {
  const observations: DebugFinding[] = [];

  if (decode.ok) {
    observations.push({
      id: "observation.decode_not_trust",
      category: "structure",
      label: "Decode vs trust",
      outcome: "info",
      severity: "info",
      message:
        "Header and payload decoded locally. Decoding does not establish trust or verify the signature.",
    });
  }

  if (algorithm === "none") {
    observations.push({
      id: "observation.alg_none",
      category: "header",
      label: "Unsigned algorithm",
      outcome: "warning",
      severity: "warning",
      message:
        'The token declares alg "none". Unsigned tokens must not be accepted in production.',
      actual: "none",
    });
  } else if (algorithm && !isSupportedAlgorithm(algorithm)) {
    observations.push({
      id: "observation.unsupported_alg",
      category: "header",
      label: "Unsupported algorithm",
      outcome: "warning",
      severity: "warning",
      message: `Algorithm "${algorithm}" is not supported for verification in this workbench.`,
      actual: algorithm,
    });
  }

  return observations;
}

function keyMatchingFindings(
  report: KeyMatchingReport,
  tokenAlg: string | null,
): DebugFinding[] {
  const findings: DebugFinding[] = [];

  if (report.parseError) {
    findings.push({
      id: "key_matching.parse",
      category: "key_matching",
      label: "JWKS parsing",
      outcome: "fail",
      severity: "error",
      message: report.parseError,
    });
    return findings;
  }

  if (!report.keys || !report.kidMatch) {
    return findings;
  }

  const matchOutcome =
    report.kidMatch.code === "NO_MATCH"
      ? "fail"
      : report.kidMatch.code === "MULTIPLE_MATCHES"
        ? "warning"
        : "info";

  findings.push({
    id: "key_matching.kid",
    category: "key_matching",
    label: "JWKS kid match",
    outcome: matchOutcome,
    severity:
      report.kidMatch.code === "NO_MATCH"
        ? "error"
        : report.kidMatch.code === "MULTIPLE_MATCHES"
          ? "warning"
          : "info",
    message: report.kidMatch.message,
  });

  if (report.selectedKeyIndex !== null) {
    const entry = report.keys.find((k) => k.index === report.selectedKeyIndex);
    if (entry) {
      const compatible = report.selectedKeyCompatible === true;
      findings.push({
        id: "key_matching.selected",
        category: "key_matching",
        label: "Selected verification key",
        outcome: compatible ? "pass" : "warning",
        severity: compatible ? "info" : "warning",
        message: compatible
          ? `Key index ${entry.index} (kid ${entry.kid ?? "—"}) is compatible with the token algorithm.`
          : `Key index ${entry.index} (kid ${entry.kid ?? "—"}) may not fit the token: ${report.selectedKeyReasons.join(" ")}`,
        actual: entry.kid ?? `index ${entry.index}`,
      });
    }
  } else if (
    report.kidMatch.code === "SINGLE_MATCH" &&
    report.kidMatch.matchedIndices.length === 1
  ) {
    const index = report.kidMatch.matchedIndices[0];
    const entry = report.keys.find((k) => k.index === index);
    if (entry) {
      const compat = jwkCompatibility(entry.jwk, tokenAlg);
      findings.push({
        id: "key_matching.auto_candidate",
        category: "key_matching",
        label: "Matched JWKS key",
        outcome: compat.compatible ? "info" : "warning",
        severity: compat.compatible ? "info" : "warning",
        message: compat.compatible
          ? `One JWKS key matches kid "${entry.kid ?? "—"}" and appears compatible with ${tokenAlg ?? "the token algorithm"}.`
          : `Matched key kid "${entry.kid ?? "—"}" has compatibility concerns: ${compat.reasons.join(" ")}`,
        actual: entry.kid ?? `index ${entry.index}`,
      });
    }
  }

  return findings;
}

function buildKeyMatchingReport(
  jwksText: string | undefined,
  tokenKid: string | null,
  tokenAlg: string | null,
  selectedJwksKeyIndex: number | null | undefined,
): KeyMatchingReport | null {
  const trimmed = jwksText?.trim();
  if (!trimmed) {
    return null;
  }

  const parsed = parseJwksText(trimmed);
  if (parsed.code !== "OK") {
    return {
      supplied: true,
      parseError: parsed.message,
      keys: null,
      kidMatch: null,
      selectedKeyIndex: selectedJwksKeyIndex ?? null,
      selectedKeyCompatible: null,
      selectedKeyReasons: [],
    };
  }

  const kidMatch = matchKeysByKid(parsed.keys, tokenKid);
  let selectedKeyCompatible: boolean | null = null;
  let selectedKeyReasons: string[] = [];

  if (selectedJwksKeyIndex !== null && selectedJwksKeyIndex !== undefined) {
    const entry = parsed.keys.find((k) => k.index === selectedJwksKeyIndex);
    if (entry) {
      const compat = jwkCompatibility(entry.jwk, tokenAlg);
      selectedKeyCompatible = compat.compatible;
      selectedKeyReasons = compat.reasons;
    }
  }

  return {
    supplied: true,
    parseError: null,
    keys: parsed.keys,
    kidMatch,
    selectedKeyIndex: selectedJwksKeyIndex ?? null,
    selectedKeyCompatible,
    selectedKeyReasons,
  };
}

function isValidationFailure(finding: DebugFinding): boolean {
  return finding.outcome === "fail" && finding.severity === "error";
}

function isObservation(finding: DebugFinding): boolean {
  if (finding.id.startsWith("observation.")) {
    return true;
  }
  if (
    finding.severity === "warning" &&
    (finding.category === "header" || finding.category === "key_matching")
  ) {
    return true;
  }
  return false;
}

export function buildJwtDebugReport(
  raw: string,
  options: DebugJwtOptions = {},
): JwtDebugReport {
  const now = options.now ?? new Date();
  const validation = validateJwt(raw, {
    expectedIssuer: options.expectedIssuer,
    expectedAudience: options.expectedAudience,
    clockToleranceSeconds: options.clockToleranceSeconds,
    signature: options.signature,
    now,
  });

  const decode = validation.decode;
  const algorithm = decode.ok ? jwtHeaderAlgorithm(decode.header) : null;
  const kid = decode.ok ? extractKid(decode.header) : null;

  const claims =
    decode.ok && typeof decode.payload === "object" && decode.payload !== null
      ? inspectPayloadClaims(decode.payload, now)
      : [];

  const keyMatching = buildKeyMatchingReport(
    options.jwksText,
    kid,
    algorithm,
    options.selectedJwksKeyIndex,
  );

  const findings: DebugFinding[] = [
    ...validation.checks.map(checkToFinding),
    ...headerFindings(decode, algorithm, kid),
    ...securityObservations(decode, algorithm),
  ];

  if (keyMatching) {
    findings.push(...keyMatchingFindings(keyMatching, algorithm));
  }

  const failures = findings.filter(isValidationFailure);
  const observations = findings.filter(
    (finding) => !isValidationFailure(finding) && isObservation(finding),
  );

  return {
    decode,
    algorithm,
    kid,
    validation,
    claims,
    keyMatching,
    findings,
    failures,
    observations,
  };
}
