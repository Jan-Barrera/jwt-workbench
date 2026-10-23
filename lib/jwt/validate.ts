import { decodeJwt, type JwtDecodeResult } from "./decode";

export type ValidationSeverity = "error" | "warning" | "info";

export type ValidationOutcome =
  | "pass"
  | "fail"
  | "warning"
  | "info"
  | "not_verified"
  | "skipped";

export type ValidationCheckId =
  | "structure"
  | "expiration"
  | "not_before"
  | "issuer"
  | "audience"
  | "signature";

export type ValidationCheck = {
  id: ValidationCheckId;
  label: string;
  outcome: ValidationOutcome;
  severity: ValidationSeverity;
  message: string;
  expected?: string;
  actual?: string;
};

export type SignatureVerificationResult =
  | { status: "not_verified"; message?: string; algorithm?: string | null }
  | { status: "pass"; message?: string; algorithm?: string | null }
  | { status: "fail"; message: string; algorithm?: string | null }
  | { status: "error"; message: string; algorithm?: string | null };

export type ValidateJwtOptions = {
  expectedIssuer?: string;
  expectedAudience?: string;
  clockToleranceSeconds?: number;
  signature?: SignatureVerificationResult;
  now?: Date;
};

export type ValidateJwtResult = {
  checks: ValidationCheck[];
  decode: JwtDecodeResult;
};

function isNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function formatClaimValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map((item) => formatClaimValue(item)).join(", ");
  }
  return JSON.stringify(value);
}

function normalizeTolerance(seconds: number | undefined): number {
  if (seconds === undefined || !Number.isFinite(seconds)) return 0;
  return Math.max(0, seconds);
}

function skippedChecks(
  reason: string,
  signature?: SignatureVerificationResult,
): ValidationCheck[] {
  const skipped: ValidationCheck[] = [
    {
      id: "expiration",
      label: "Expiration",
      outcome: "skipped",
      severity: "info",
      message: reason,
    },
    {
      id: "not_before",
      label: "Not Before",
      outcome: "skipped",
      severity: "info",
      message: reason,
    },
    {
      id: "issuer",
      label: "Issuer",
      outcome: "skipped",
      severity: "info",
      message: reason,
    },
    {
      id: "audience",
      label: "Audience",
      outcome: "skipped",
      severity: "info",
      message: reason,
    },
  ];
  skipped.push(signatureCheck(signature));
  return skipped;
}

function evaluateExpiration(
  exp: unknown,
  nowSec: number,
  toleranceSec: number,
): ValidationCheck {
  if (exp === undefined) {
    return {
      id: "expiration",
      label: "Expiration",
      outcome: "info",
      severity: "info",
      message: "No exp claim present.",
    };
  }
  if (!isNumericDate(exp)) {
    return {
      id: "expiration",
      label: "Expiration",
      outcome: "fail",
      severity: "error",
      message: "exp must be a numeric Unix timestamp.",
      actual: formatClaimValue(exp),
    };
  }

  const effectiveNow = nowSec - toleranceSec;
  if (effectiveNow >= exp) {
    return {
      id: "expiration",
      label: "Expiration",
      outcome: "fail",
      severity: "error",
      message: `Token expired at ${exp} (Unix seconds).`,
      actual: String(exp),
    };
  }

  return {
    id: "expiration",
    label: "Expiration",
    outcome: "pass",
    severity: "info",
    message: toleranceSec > 0
      ? `Token is not expired (clock tolerance ${toleranceSec}s applied).`
      : "Token is not expired.",
  };
}

function evaluateNotBefore(
  nbf: unknown,
  nowSec: number,
  toleranceSec: number,
): ValidationCheck {
  if (nbf === undefined) {
    return {
      id: "not_before",
      label: "Not Before",
      outcome: "info",
      severity: "info",
      message: "No nbf claim present.",
    };
  }
  if (!isNumericDate(nbf)) {
    return {
      id: "not_before",
      label: "Not Before",
      outcome: "fail",
      severity: "error",
      message: "nbf must be a numeric Unix timestamp.",
      actual: formatClaimValue(nbf),
    };
  }

  const effectiveNow = nowSec + toleranceSec;
  if (effectiveNow < nbf) {
    return {
      id: "not_before",
      label: "Not Before",
      outcome: "fail",
      severity: "error",
      message: `Token is not valid until ${nbf} (Unix seconds).`,
      actual: String(nbf),
    };
  }

  return {
    id: "not_before",
    label: "Not Before",
    outcome: "pass",
    severity: "info",
    message: toleranceSec > 0
      ? `nbf satisfied (clock tolerance ${toleranceSec}s applied).`
      : "nbf satisfied.",
  };
}

function evaluateIssuer(
  iss: unknown,
  expectedIssuer?: string,
): ValidationCheck {
  const expected = expectedIssuer?.trim();
  if (!expected) {
    return {
      id: "issuer",
      label: "Issuer",
      outcome: "info",
      severity: "info",
      message: "No expected issuer configured.",
      actual: iss === undefined ? undefined : formatClaimValue(iss),
    };
  }

  if (typeof iss !== "string") {
    return {
      id: "issuer",
      label: "Issuer",
      outcome: "fail",
      severity: "error",
      message: "Token has no string iss claim.",
      expected,
      actual: iss === undefined ? "(missing)" : formatClaimValue(iss),
    };
  }

  if (iss !== expected) {
    return {
      id: "issuer",
      label: "Issuer",
      outcome: "fail",
      severity: "error",
      message: `Issuer mismatch.`,
      expected,
      actual: iss,
    };
  }

  return {
    id: "issuer",
    label: "Issuer",
    outcome: "pass",
    severity: "info",
    message: "Issuer matches the expected value.",
    expected,
    actual: iss,
  };
}

function audienceMatches(expected: string, aud: unknown): boolean {
  if (typeof aud === "string") {
    return aud === expected;
  }
  if (Array.isArray(aud)) {
    return aud.some((item) => typeof item === "string" && item === expected);
  }
  return false;
}

function evaluateAudience(
  aud: unknown,
  expectedAudience?: string,
): ValidationCheck {
  const expected = expectedAudience?.trim();
  if (!expected) {
    return {
      id: "audience",
      label: "Audience",
      outcome: "info",
      severity: "info",
      message: "No expected audience configured.",
      actual: aud === undefined ? undefined : formatClaimValue(aud),
    };
  }

  if (aud === undefined) {
    return {
      id: "audience",
      label: "Audience",
      outcome: "fail",
      severity: "error",
      message: "Token has no aud claim.",
      expected,
      actual: "(missing)",
    };
  }

  if (!audienceMatches(expected, aud)) {
    return {
      id: "audience",
      label: "Audience",
      outcome: "fail",
      severity: "error",
      message: "Audience mismatch.",
      expected,
      actual: formatClaimValue(aud),
    };
  }

  return {
    id: "audience",
    label: "Audience",
    outcome: "pass",
    severity: "info",
    message: "Audience matches the expected value.",
    expected,
    actual: formatClaimValue(aud),
  };
}

export function signatureCheck(
  result?: SignatureVerificationResult,
): ValidationCheck {
  const resolved = result ?? { status: "not_verified" as const };

  switch (resolved.status) {
    case "pass":
      return {
        id: "signature",
        label: "Signature",
        outcome: "pass",
        severity: "info",
        message: resolved.message ?? "Signature verified.",
      };
    case "fail":
      return {
        id: "signature",
        label: "Signature",
        outcome: "fail",
        severity: "error",
        message: resolved.message,
      };
    case "error":
      return {
        id: "signature",
        label: "Signature",
        outcome: "fail",
        severity: "error",
        message: resolved.message,
      };
    case "not_verified":
    default:
      return {
        id: "signature",
        label: "Signature",
        outcome: "not_verified",
        severity: "info",
        message:
          resolved.status === "not_verified" && resolved.message
            ? resolved.message
            : "No verification key or material supplied.",
      };
  }
}

function isClaimObject(payload: unknown): payload is Record<string, unknown> {
  return typeof payload === "object" && payload !== null && !Array.isArray(payload);
}

export function validateJwt(
  raw: string,
  options: ValidateJwtOptions = {},
): ValidateJwtResult {
  const toleranceSec = normalizeTolerance(options.clockToleranceSeconds);
  const nowSec = (options.now ?? new Date()).getTime() / 1000;
  const decoded = decodeJwt(raw);

  if (!decoded.ok) {
    return {
      decode: decoded,
      checks: [
        {
          id: "structure",
          label: "Token structure",
          outcome: "fail",
          severity: "error",
          message: decoded.error,
        },
        ...skippedChecks(
          "Cannot evaluate claims until token structure is valid.",
          options.signature,
        ),
      ],
    };
  }

  if (!isClaimObject(decoded.payload)) {
    return {
      decode: decoded,
      checks: [
        {
          id: "structure",
          label: "Token structure",
          outcome: "warning",
          severity: "warning",
          message: "JWT payload is not a JSON object; claim checks were not run.",
        },
        ...skippedChecks(
          "Payload must be a JSON object with claims.",
          options.signature,
        ),
      ],
    };
  }

  const payload = decoded.payload;

  return {
    decode: decoded,
    checks: [
      {
        id: "structure",
        label: "Token structure",
        outcome: "pass",
        severity: "info",
        message: "Valid compact JWT with decodable header and payload.",
      },
      evaluateExpiration(payload.exp, nowSec, toleranceSec),
      evaluateNotBefore(payload.nbf, nowSec, toleranceSec),
      evaluateIssuer(payload.iss, options.expectedIssuer),
      evaluateAudience(payload.aud, options.expectedAudience),
      signatureCheck(options.signature),
    ],
  };
}
