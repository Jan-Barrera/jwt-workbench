/** Placeholder used when redacting JWTs, keys, and secrets from logs or telemetry. */
export const REDACTED = "[REDACTED]";

const COMPACT_JWT_RE =
  /\b(?:Bearer\s+)?eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gi;

const PRIVATE_PEM_RE =
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g;

const PRIVATE_JWK_FIELD_RE =
  /"(d|p|q|dp|dq|qi|oth)"\s*:\s*(?:"(?:\\.|[^"\\])*"|\[[^\]]*\])/g;

/** Field names that commonly hold secrets in structured payloads. */
const SENSITIVE_FIELD_NAMES = new Set([
  "password",
  "secret",
  "token",
  "jwt",
  "access_token",
  "id_token",
  "refresh_token",
  "bearer",
  "authorization",
  "api_key",
  "apikey",
  "private_key",
  "privatekey",
  "client_secret",
  "key_material",
  "keymaterial",
]);

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;

/** Returns true when a string resembles a compact JWT (three Base64URL segments). */
export function looksLikeJwt(value: string): boolean {
  const normalized = value.trim().replace(/^Bearer\s+/i, "");
  const parts = normalized.split(".");
  if (parts.length !== 3) {
    return false;
  }
  if (
    !parts.every(
      (part) => part.length >= 10 && BASE64URL_SEGMENT.test(part),
    )
  ) {
    return false;
  }
  // JSON object headers encode to Base64URL starting with eyJ ({"…).
  return parts[0].startsWith("eyJ");
}

function isSensitiveFieldName(name: string): boolean {
  const lower = name.toLowerCase();
  if (SENSITIVE_FIELD_NAMES.has(lower)) {
    return true;
  }
  return (
    lower.includes("token") ||
    lower.includes("secret") ||
    lower.includes("password") ||
    lower.endsWith("_key") ||
    lower === "key"
  );
}

/** Redacts JWT-shaped strings, private PEM blocks, and private JWK fields from free text. */
export function scrubSensitiveText(input: string): string {
  let out = input.replace(PRIVATE_PEM_RE, REDACTED);
  out = out.replace(COMPACT_JWT_RE, REDACTED);
  out = out.replace(
    PRIVATE_JWK_FIELD_RE,
    (_match, field: string) => `"${field}": "${REDACTED}"`,
  );
  return out;
}

const MAX_SCRUB_DEPTH = 12;

/** Recursively redacts sensitive strings and known secret field names in arbitrary values. */
export function scrubSensitiveValue(
  value: unknown,
  depth = 0,
): unknown {
  if (depth > MAX_SCRUB_DEPTH) {
    return REDACTED;
  }

  if (typeof value === "string") {
    if (looksLikeJwt(value)) {
      return REDACTED;
    }
    return scrubSensitiveText(value);
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: scrubSensitiveText(value.message),
      stack: value.stack ? scrubSensitiveText(value.stack) : undefined,
    };
  }

  if (Array.isArray(value)) {
    return value.map((entry) => scrubSensitiveValue(entry, depth + 1));
  }

  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      if (isSensitiveFieldName(key)) {
        out[key] = REDACTED;
      } else if (typeof entry === "string" && looksLikeJwt(entry)) {
        out[key] = REDACTED;
      } else {
        out[key] = scrubSensitiveValue(entry, depth + 1);
      }
    }
    return out;
  }

  return value;
}

/** Formats an unknown error for safe logging or telemetry (no token or key material). */
export function formatErrorForReporting(error: unknown): string {
  if (error instanceof Error) {
    return scrubSensitiveText(`${error.name}: ${error.message}`);
  }
  if (typeof error === "string") {
    return scrubSensitiveText(error);
  }
  try {
    return scrubSensitiveText(JSON.stringify(scrubSensitiveValue(error)));
  } catch {
    return "Unknown error";
  }
}
