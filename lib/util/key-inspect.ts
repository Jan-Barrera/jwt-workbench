import { exportJWK, importSPKI, importX509, type JWK } from "jose";

export type SafeJwkField = {
  name: string;
  value: string;
};

export type InspectedKeyEntry = {
  label: string;
  kty: string | null;
  fields: SafeJwkField[];
  warnings: string[];
  safeJson: string;
};

export type KeyInspectSuccess = {
  ok: true;
  format: "jwk" | "jwks" | "pem";
  entries: InspectedKeyEntry[];
};

export type KeyInspectError = {
  ok: false;
  message: string;
};

export type KeyInspectResult = KeyInspectSuccess | KeyInspectError;

const PRIVATE_PEM_LABELS = new Set([
  "PRIVATE KEY",
  "RSA PRIVATE KEY",
  "EC PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
]);

const PRIVATE_JWK_FIELDS = new Set([
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJwk(value: unknown): value is JWK {
  return isRecord(value) && typeof value.kty === "string";
}

function isJwks(value: unknown): value is { keys: unknown[] } {
  return isRecord(value) && Array.isArray(value.keys);
}

function pemLabel(material: string): string | null {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(material);
  return match?.[1] ?? null;
}

function detectInputFormat(text: string): "jwk" | "pem" | "unknown" {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return "jwk";
  if (trimmed.includes("-----BEGIN ")) return "pem";
  return "unknown";
}

function formatFieldValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function sanitizeJwkFields(jwk: JWK): {
  fields: SafeJwkField[];
  warnings: string[];
  kty: string;
} {
  const warnings: string[] = [];
  const fields: SafeJwkField[] = [];
  const kty = jwk.kty as string;

  if (kty === "oct") {
    warnings.push(
      "Symmetric (oct) JWKs contain secret key material. Only metadata is shown.",
    );
  }

  for (const [name, value] of Object.entries(jwk)) {
    if (PRIVATE_JWK_FIELDS.has(name)) {
      warnings.push(`Private field "${name}" was omitted.`);
      continue;
    }
    if (kty === "oct" && name === "k") {
      continue;
    }
    if (value === undefined || value === null) {
      continue;
    }
    fields.push({ name, value: formatFieldValue(value) });
  }

  fields.sort((a, b) => a.name.localeCompare(b.name));

  return { fields, warnings, kty };
}

function buildSafeJson(jwk: JWK): string {
  const safe: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(jwk)) {
    if (PRIVATE_JWK_FIELDS.has(name)) continue;
    if (jwk.kty === "oct" && name === "k") continue;
    if (value !== undefined) {
      safe[name] = value;
    }
  }
  return JSON.stringify(safe, null, 2);
}

function inspectJwkObject(jwk: JWK, label: string): InspectedKeyEntry {
  const { fields, warnings, kty } = sanitizeJwkFields(jwk);
  return {
    label,
    kty,
    fields,
    warnings,
    safeJson: buildSafeJson(jwk),
  };
}

function inspectParsedJson(parsed: unknown): KeyInspectResult {
  if (isJwks(parsed)) {
    const entries: InspectedKeyEntry[] = [];
    for (let index = 0; index < parsed.keys.length; index += 1) {
      const entry = parsed.keys[index];
      if (!isJwk(entry)) {
        continue;
      }
      entries.push(
        inspectJwkObject(
          entry,
          typeof entry.kid === "string" ? `Key ${entry.kid}` : `Key #${index}`,
        ),
      );
    }
    if (entries.length === 0) {
      return {
        ok: false,
        message: "JWKS does not contain any keys with a kty field.",
      };
    }
    return { ok: true, format: "jwks", entries };
  }

  if (isJwk(parsed)) {
    const label =
      typeof parsed.kid === "string" ? `Key ${parsed.kid}` : "JWK";
    return {
      ok: true,
      format: "jwk",
      entries: [inspectJwkObject(parsed, label)],
    };
  }

  return {
    ok: false,
    message: "JSON is not a JWK or JWKS object.",
  };
}

async function importPemPublicKey(
  material: string,
  label: string,
): Promise<InspectedKeyEntry | KeyInspectError> {
  if (PRIVATE_PEM_LABELS.has(label)) {
    return {
      ok: false,
      message:
        "Private key PEM detected. Paste a public key (SPKI), certificate, or JWK.",
    };
  }

  if (label === "RSA PUBLIC KEY") {
    return {
      ok: false,
      message:
        "PKCS#1 RSA public keys are not supported. Use SPKI (BEGIN PUBLIC KEY) or a JWK.",
    };
  }

  const importAttempts: Array<{ alg: string; importFn: () => Promise<CryptoKey> }> =
    [];

  if (label === "PUBLIC KEY") {
    importAttempts.push(
      { alg: "RS256", importFn: () => importSPKI(material, "RS256") },
      { alg: "PS256", importFn: () => importSPKI(material, "PS256") },
      { alg: "ES256", importFn: () => importSPKI(material, "ES256") },
      { alg: "ES384", importFn: () => importSPKI(material, "ES384") },
      { alg: "ES512", importFn: () => importSPKI(material, "ES512") },
      { alg: "EdDSA", importFn: () => importSPKI(material, "EdDSA") },
    );
  } else if (label === "CERTIFICATE") {
    importAttempts.push(
      { alg: "RS256", importFn: () => importX509(material, "RS256") },
      { alg: "PS256", importFn: () => importX509(material, "PS256") },
      { alg: "ES256", importFn: () => importX509(material, "ES256") },
      { alg: "ES384", importFn: () => importX509(material, "ES384") },
      { alg: "ES512", importFn: () => importX509(material, "ES512") },
      { alg: "EdDSA", importFn: () => importX509(material, "EdDSA") },
    );
  } else {
    return {
      ok: false,
      message: `Unsupported PEM type "${label}". Use a public key, certificate, or JWK.`,
    };
  }

  for (const attempt of importAttempts) {
    try {
      const key = await attempt.importFn();
      const jwk = (await exportJWK(key)) as JWK;
      const entry = inspectJwkObject(jwk, `PEM (${label})`);
      entry.warnings.push(`Imported as ${attempt.alg} for metadata extraction.`);
      return entry;
    } catch {
      continue;
    }
  }

  return {
    ok: false,
    message: "PEM key could not be parsed as a supported public key.",
  };
}

export async function inspectKeyMaterial(text: string): Promise<KeyInspectResult> {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false, message: "Paste a PEM public key, certificate, or JWK." };
  }

  const format = detectInputFormat(trimmed);
  if (format === "unknown") {
    return {
      ok: false,
      message: "Input is not recognized as PEM or JSON JWK/JWKS.",
    };
  }

  if (format === "jwk") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return { ok: false, message: "Key material is not valid JSON." };
    }
    return inspectParsedJson(parsed);
  }

  const label = pemLabel(trimmed);
  if (!label) {
    return { ok: false, message: "PEM block is malformed." };
  }

  const entry = await importPemPublicKey(trimmed, label);
  if ("ok" in entry && entry.ok === false) {
    return entry;
  }

  return {
    ok: true,
    format: "pem",
    entries: [entry as InspectedKeyEntry],
  };
}
