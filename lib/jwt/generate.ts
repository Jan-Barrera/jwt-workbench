import {
  SignJWT,
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  importJWK,
  importPKCS8,
  type CryptoKey,
  type JWK,
  type JWSAlgorithm,
} from "jose";

import {
  SUPPORTED_ALGORITHMS,
  isHmacAlgorithm,
  isSupportedAlgorithm,
  type SupportedAlgorithm,
} from "./verify";

export { SUPPORTED_ALGORITHMS, type SupportedAlgorithm };

export type SignKeyFormat = "auto" | "secret" | "pem" | "jwk";

export type GenerateJwtCode =
  | "PASS"
  | "INVALID_HEADER"
  | "INVALID_PAYLOAD"
  | "INVALID_CLAIM_VALUE"
  | "UNSUPPORTED_ALGORITHM"
  | "MISSING_KEY"
  | "MALFORMED_KEY"
  | "KEY_TYPE_MISMATCH"
  | "SIGN_FAILED";

export type GenerateJwtSuccess = {
  ok: true;
  code: "PASS";
  token: string;
  message: string;
};

export type GenerateJwtError = {
  ok: false;
  code: Exclude<GenerateJwtCode, "PASS">;
  message: string;
  field?: "header" | "payload" | "key" | "claim";
};

export type GenerateJwtResult = GenerateJwtSuccess | GenerateJwtError;

export type PayloadFieldInput = {
  iss?: string;
  sub?: string;
  aud?: string;
  iat?: string;
  nbf?: string;
  exp?: string;
  jti?: string;
  customClaims?: { name: string; value: string }[];
};

export type GenerateJwtOptions = {
  algorithm: SupportedAlgorithm;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  keyMaterial?: string;
  keyFormat?: SignKeyFormat;
};

export type LocalKeyPairResult =
  | {
      ok: true;
      privateKeyMaterial: string;
      publicKeyMaterial: string;
      message: string;
    }
  | { ok: false; message: string };

const PRIVATE_PEM_LABELS = [
  "PRIVATE KEY",
  "RSA PRIVATE KEY",
  "EC PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
];

export function parseJsonObject(
  raw: string,
  label: "Header" | "Payload",
): { ok: true; value: Record<string, unknown> } | GenerateJwtError {
  const trimmed = raw.trim();
  if (!trimmed) {
    return error(
      label === "Header" ? "INVALID_HEADER" : "INVALID_PAYLOAD",
      `${label} JSON is empty.`,
      label === "Header" ? "header" : "payload",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return error(
      label === "Header" ? "INVALID_HEADER" : "INVALID_PAYLOAD",
      `${label} is not valid JSON.`,
      label === "Header" ? "header" : "payload",
    );
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return error(
      label === "Header" ? "INVALID_HEADER" : "INVALID_PAYLOAD",
      `${label} must be a JSON object.`,
      label === "Header" ? "header" : "payload",
    );
  }

  return { ok: true, value: parsed as Record<string, unknown> };
}

export function buildHeaderObject(
  algorithm: SupportedAlgorithm,
  fields: { typ?: string; kid?: string },
): Record<string, unknown> {
  const header: Record<string, unknown> = {
    alg: headerAlgorithmLabel(algorithm),
    typ: fields.typ?.trim() || "JWT",
  };
  const kid = fields.kid?.trim();
  if (kid) {
    header.kid = kid;
  }
  return header;
}

export function buildPayloadFromFields(
  fields: PayloadFieldInput,
): { ok: true; payload: Record<string, unknown> } | GenerateJwtError {
  const payload: Record<string, unknown> = {};

  const stringClaims = ["iss", "sub", "jti"] as const;
  for (const name of stringClaims) {
    const value = fields[name]?.trim();
    if (value) {
      payload[name] = value;
    }
  }

  const aud = fields.aud?.trim();
  if (aud) {
    if (aud.includes(",")) {
      payload.aud = aud
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);
    } else {
      payload.aud = aud;
    }
  }

  for (const name of ["iat", "nbf", "exp"] as const) {
    const raw = fields[name]?.trim();
    if (!raw) continue;
    const seconds = Number.parseInt(raw, 10);
    if (!Number.isFinite(seconds)) {
      return error(
        "INVALID_CLAIM_VALUE",
        `${name.toUpperCase()} must be a Unix timestamp in seconds.`,
        "claim",
      );
    }
    payload[name] = seconds;
  }

  for (const claim of fields.customClaims ?? []) {
    const name = claim.name.trim();
    if (!name) {
      return error(
        "INVALID_CLAIM_VALUE",
        "Custom claim names cannot be empty.",
        "claim",
      );
    }
    if (name in payload) {
      return error(
        "INVALID_CLAIM_VALUE",
        `Duplicate claim "${name}".`,
        "claim",
      );
    }
    const parsed = parseClaimValue(claim.value);
    if (!parsed.ok) {
      return parsed;
    }
    payload[name] = parsed.value;
  }

  return { ok: true, payload };
}

function joseCryptoAlgorithm(algorithm: SupportedAlgorithm): JWSAlgorithm {
  if (algorithm === "Ed25519") return "EdDSA";
  return algorithm as JWSAlgorithm;
}

function headerAlgorithmLabel(algorithm: SupportedAlgorithm): string {
  if (algorithm === "Ed25519") return "EdDSA";
  return algorithm;
}

function headerAlgorithmsMatch(
  headerAlg: string,
  selected: SupportedAlgorithm,
): boolean {
  if (headerAlg === selected) return true;
  if (
    (headerAlg === "EdDSA" && selected === "Ed25519") ||
    (headerAlg === "Ed25519" && selected === "EdDSA")
  ) {
    return true;
  }
  return false;
}

export function normalizeHeaderForSign(
  header: Record<string, unknown>,
  algorithm: SupportedAlgorithm,
): { ok: true; header: Record<string, unknown> } | GenerateJwtError {
  const next = { ...header };
  const alg = next.alg;
  if (typeof alg === "string" && !headerAlgorithmsMatch(alg, algorithm)) {
    return error(
      "INVALID_HEADER",
      `Header alg "${alg}" does not match selected algorithm ${algorithm}.`,
      "header",
    );
  }
  if (alg === "none") {
    return error(
      "INVALID_HEADER",
      'The "none" algorithm cannot be used to sign tokens.',
      "header",
    );
  }
  next.alg = headerAlgorithmLabel(algorithm);
  if (typeof next.typ !== "string" || !next.typ.trim()) {
    next.typ = "JWT";
  }
  return { ok: true, header: next };
}

export async function generateJwt(
  options: GenerateJwtOptions,
): Promise<GenerateJwtResult> {
  const algorithm = options.algorithm;
  if (!isSupportedAlgorithm(algorithm)) {
    return error("UNSUPPORTED_ALGORITHM", `Unsupported algorithm "${algorithm}".`);
  }

  const headerResult = normalizeHeaderForSign(options.header, algorithm);
  if (!headerResult.ok) {
    return headerResult;
  }

  const payload = options.payload;
  if (
    typeof payload !== "object" ||
    payload === null ||
    Array.isArray(payload)
  ) {
    return error("INVALID_PAYLOAD", "Payload must be a JSON object.", "payload");
  }

  const keyMaterial = options.keyMaterial?.trim() ?? "";
  if (!keyMaterial) {
    return error(
      "MISSING_KEY",
      "Paste a signing secret or private key to sign the token.",
      "key",
    );
  }

  const format =
    options.keyFormat && options.keyFormat !== "auto"
      ? options.keyFormat
      : detectSignKeyFormat(keyMaterial);

  const keyOrError = await importSigningKey({
    alg: algorithm,
    format,
    keyMaterial,
  });
  if (!keyOrError.ok) {
    return keyOrError;
  }

  try {
    const signer = new SignJWT(payload as Record<string, unknown>);
    const token = await signer
      .setProtectedHeader(
        headerResult.header as Parameters<SignJWT["setProtectedHeader"]>[0],
      )
      .sign(keyOrError.key);
    return {
      ok: true,
      code: "PASS",
      token,
      message: `Signed with ${algorithm}.`,
    };
  } catch {
    return error(
      "SIGN_FAILED",
      "Signing failed. Check key material and claim values.",
      "key",
    );
  }
}

export async function createLocalSigningMaterial(
  algorithm: SupportedAlgorithm,
): Promise<LocalKeyPairResult> {
  if (!isSupportedAlgorithm(algorithm)) {
    return { ok: false, message: `Unsupported algorithm "${algorithm}".` };
  }

  try {
    if (isHmacAlgorithm(algorithm)) {
      const secretBytes = new Uint8Array(32);
      if (typeof crypto !== "undefined" && crypto.getRandomValues) {
        crypto.getRandomValues(secretBytes);
      } else {
        for (let i = 0; i < secretBytes.length; i++) {
          secretBytes[i] = Math.floor(Math.random() * 256);
        }
      }
      const material = Buffer.from(secretBytes).toString("base64url");
      return {
        ok: true,
        privateKeyMaterial: material,
        publicKeyMaterial: material,
        message: `Generated a random shared secret for ${algorithm}. Use the same value to verify.`,
      };
    }

    const pair = await generateKeyPair(joseCryptoAlgorithm(algorithm), {
      extractable: true,
    });
    const privateKeyMaterial = await exportPKCS8(pair.privateKey);
    const publicKeyMaterial = await exportSPKI(pair.publicKey);
    return {
      ok: true,
      privateKeyMaterial,
      publicKeyMaterial,
      message: `Generated a local ${algorithm} key pair. Private key signs; public key verifies.`,
    };
  } catch {
    return {
      ok: false,
      message: `Could not generate key material for ${algorithm}.`,
    };
  }
}

function parseClaimValue(
  raw: string,
): { ok: true; value: unknown } | GenerateJwtError {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: true, value: "" };
  }
  try {
    return { ok: true, value: JSON.parse(trimmed) as unknown };
  } catch {
    return { ok: true, value: raw };
  }
}

function detectSignKeyFormat(material: string): Exclude<SignKeyFormat, "auto"> {
  const trimmed = material.trim();
  if (trimmed.startsWith("{")) return "jwk";
  if (trimmed.includes("-----BEGIN ")) return "pem";
  return "secret";
}

function pemLabel(material: string): string | null {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(material);
  return match?.[1] ?? null;
}

async function importSigningKey(input: {
  alg: SupportedAlgorithm;
  format: Exclude<SignKeyFormat, "auto">;
  keyMaterial: string;
}): Promise<{ ok: true; key: CryptoKey | Uint8Array } | GenerateJwtError> {
  const { alg, format, keyMaterial } = input;

  if (isHmacAlgorithm(alg)) {
    if (format === "pem") {
      return error(
        "KEY_TYPE_MISMATCH",
        `${alg} requires a shared secret, not a PEM key.`,
        "key",
      );
    }
    if (format === "jwk") {
      return importHmacJwk(keyMaterial, alg);
    }
    return { ok: true, key: new TextEncoder().encode(keyMaterial) };
  }

  if (format === "secret") {
    return error(
      "KEY_TYPE_MISMATCH",
      `${alg} requires a private key (PEM or JWK), not a shared secret.`,
      "key",
    );
  }

  if (format === "pem") {
    return importPrivatePem(keyMaterial, alg);
  }

  return importPrivateJwk(keyMaterial, alg);
}

async function importPrivatePem(
  material: string,
  alg: SupportedAlgorithm,
): Promise<{ ok: true; key: CryptoKey } | GenerateJwtError> {
  const label = pemLabel(material);
  if (!label || !PRIVATE_PEM_LABELS.includes(label)) {
    return error(
      "MALFORMED_KEY",
      "Paste a PKCS#8 private key (BEGIN PRIVATE KEY) or algorithm-specific private PEM.",
      "key",
    );
  }

  try {
    const key = await importPKCS8(material, joseCryptoAlgorithm(alg));
    return { ok: true, key };
  } catch {
    return error(
      "MALFORMED_KEY",
      "Private key PEM is malformed or does not match the selected algorithm.",
      "key",
    );
  }
}

async function importPrivateJwk(
  material: string,
  alg: SupportedAlgorithm,
): Promise<{ ok: true; key: CryptoKey } | GenerateJwtError> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(material);
  } catch {
    return error("MALFORMED_KEY", "JWK JSON is not valid.", "key");
  }

  if (!isJwk(parsed)) {
    return error("MALFORMED_KEY", "Key material is not a JWK.", "key");
  }

  if (parsed.kty === "oct") {
    return error(
      "KEY_TYPE_MISMATCH",
      `${alg} requires a private asymmetric JWK, not an oct key.`,
      "key",
    );
  }

  try {
    const key = await importJWK(parsed, joseCryptoAlgorithm(alg));
    if (!(key instanceof CryptoKey)) {
      return error(
        "MALFORMED_KEY",
        "JWK did not import as a private signing key.",
        "key",
      );
    }
    return { ok: true, key };
  } catch {
    return error(
      "MALFORMED_KEY",
      "JWK is malformed or missing private key parameters.",
      "key",
    );
  }
}

async function importHmacJwk(
  material: string,
  alg: SupportedAlgorithm,
): Promise<{ ok: true; key: Uint8Array } | GenerateJwtError> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(material);
  } catch {
    return error("MALFORMED_KEY", "JWK JSON is not valid.", "key");
  }

  if (!isJwk(parsed) || parsed.kty !== "oct") {
    return error(
      "KEY_TYPE_MISMATCH",
      `${alg} JWK must have kty "oct".`,
      "key",
    );
  }

  try {
    const key = await importJWK(parsed, alg);
    if (key instanceof Uint8Array) {
      return { ok: true, key };
    }
    if (key instanceof CryptoKey) {
      const jwk = (await exportJWK(key)) as JWK;
      if (typeof jwk.k === "string") {
        return { ok: true, key: Buffer.from(jwk.k, "base64url") };
      }
    }
    return error("MALFORMED_KEY", "HMAC JWK could not be used as a secret.", "key");
  } catch {
    return error("MALFORMED_KEY", "HMAC JWK is malformed.", "key");
  }
}

function isJwk(value: unknown): value is JWK {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as JWK).kty === "string"
  );
}

function error(
  code: Exclude<GenerateJwtCode, "PASS">,
  message: string,
  field?: GenerateJwtError["field"],
): GenerateJwtError {
  return { ok: false, code, message, field };
}
