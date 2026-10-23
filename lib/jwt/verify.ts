import {
  compactVerify,
  decodeProtectedHeader,
  importJWK,
  importSPKI,
  importX509,
  errors,
  type CryptoKey,
  type JWK,
  type JWSAlgorithm,
} from "jose";

import {
  SUPPORTED_ALGORITHMS,
  expectedJwkKty,
  isHmacAlgorithm,
  isSupportedAlgorithm,
  type SupportedAlgorithm,
} from "@/lib/crypto";
import {
  detectKeyFormat,
  isPrivatePemLabel,
  pemLabel,
} from "@/lib/crypto/pem";

import { normalizeJwtInput } from "./decode";
import type { SignatureVerificationResult } from "./validate";

export {
  SUPPORTED_ALGORITHMS,
  isHmacAlgorithm,
  isSupportedAlgorithm,
  type SupportedAlgorithm,
};

export type VerifyKeyFormat = "auto" | "secret" | "pem" | "jwk";

export type VerifyJwtCode =
  | "PASS"
  | "INVALID_SIGNATURE"
  | "UNSUPPORTED_ALGORITHM"
  | "NONE_ALGORITHM"
  | "MALFORMED_KEY"
  | "MISSING_KEY"
  | "KEY_TYPE_MISMATCH"
  | "MALFORMED_TOKEN";

export type VerifyJwtResult = {
  ok: boolean;
  code: VerifyJwtCode;
  algorithm: string | null;
  message: string;
};

export type VerifyJwtOptions = {
  keyMaterial?: string;
  keyFormat?: VerifyKeyFormat;
};

export function jwtHeaderAlgorithm(header: unknown): string | null {
  if (!isRecord(header)) return null;
  return typeof header.alg === "string" ? header.alg : null;
}

export function toSignatureVerificationResult(
  result: VerifyJwtResult,
): SignatureVerificationResult {
  switch (result.code) {
    case "PASS":
      return {
        status: "pass",
        message: result.message,
        algorithm: result.algorithm,
      };
    case "MISSING_KEY":
      return {
        status: "not_verified",
        message: result.message,
        algorithm: result.algorithm,
      };
    case "INVALID_SIGNATURE":
      return {
        status: "fail",
        message: result.message,
        algorithm: result.algorithm,
      };
    default:
      return {
        status: "error",
        message: result.message,
        algorithm: result.algorithm,
      };
  }
}

export async function verifyJwt(
  raw: string,
  options: VerifyJwtOptions = {},
): Promise<VerifyJwtResult> {
  const token = normalizeJwtInput(raw);
  if (!token) {
    return verifyResult(
      "MALFORMED_TOKEN",
      null,
      "Enter a JWT to verify.",
    );
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return verifyResult(
      "MALFORMED_TOKEN",
      null,
      "Token is not a compact JWS/JWT, so the signature cannot be verified.",
    );
  }

  const alg = jwtHeaderAlgorithm(header);
  const kid = typeof header.kid === "string" ? header.kid : undefined;

  if (!alg) {
    return verifyResult(
      "UNSUPPORTED_ALGORITHM",
      null,
      "Token header has no alg.",
    );
  }

  if (alg === "none") {
    return verifyResult(
      "NONE_ALGORITHM",
      alg,
      'The "none" algorithm is not allowed.',
    );
  }

  if (!isSupportedAlgorithm(alg)) {
    return verifyResult(
      "UNSUPPORTED_ALGORITHM",
      alg,
      `Unsupported signing algorithm "${alg}".`,
    );
  }

  const keyMaterial = options.keyMaterial?.trim() ?? "";
  if (!keyMaterial) {
    return verifyResult(
      "MISSING_KEY",
      alg,
      "No verification key or material supplied.",
    );
  }

  const format =
    options.keyFormat && options.keyFormat !== "auto"
      ? options.keyFormat
      : detectKeyFormat(keyMaterial);

  const keyOrError = await importVerificationKey({
    alg,
    kid,
    format,
    keyMaterial,
  });
  if ("code" in keyOrError) {
    return keyOrError;
  }

  try {
    await compactVerify(token, keyOrError.key, {
      algorithms: [alg as JWSAlgorithm],
    });
    return verifyResult("PASS", alg, `Signature verified with ${alg}.`);
  } catch (error) {
    return mapVerifyError(error, alg);
  }
}

function verifyResult(
  code: VerifyJwtCode,
  algorithm: string | null,
  message: string,
): VerifyJwtResult {
  return {
    ok: code === "PASS",
    code,
    algorithm,
    message,
  };
}

async function importVerificationKey(input: {
  alg: SupportedAlgorithm;
  kid: string | undefined;
  format: Exclude<VerifyKeyFormat, "auto">;
  keyMaterial: string;
}): Promise<{ key: Uint8Array | CryptoKey } | VerifyJwtResult> {
  const { alg, kid, format, keyMaterial } = input;

  if (isHmacAlgorithm(alg) && detectKeyFormat(keyMaterial) === "pem") {
    return verifyResult(
      "KEY_TYPE_MISMATCH",
      alg,
      `Refusing to use a PEM key as an HMAC secret for ${alg}.`,
    );
  }

  if (!isHmacAlgorithm(alg) && format === "secret") {
    return verifyResult(
      "KEY_TYPE_MISMATCH",
      alg,
      `${alg} requires a PEM public key or JWK, not a shared secret.`,
    );
  }

  if (format === "secret") {
    return { key: new TextEncoder().encode(keyMaterial) };
  }

  if (format === "pem") {
    return importPemKey(keyMaterial, alg);
  }

  return importJsonKey(keyMaterial, alg, kid);
}

async function importPemKey(
  material: string,
  alg: SupportedAlgorithm,
): Promise<{ key: CryptoKey } | VerifyJwtResult> {
  const label = pemLabel(material);
  if (!label) {
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      "PEM key material is malformed.",
    );
  }

  if (isPrivatePemLabel(label)) {
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      "Paste a public key or JWK. Private keys are not used for verification.",
    );
  }

  if (label === "RSA PUBLIC KEY") {
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      "PKCS#1 RSA public keys are not supported. Use a SPKI public key (BEGIN PUBLIC KEY) or a JWK.",
    );
  }

  try {
    if (label === "CERTIFICATE") {
      return { key: await importX509(material, alg) };
    }
    if (label === "PUBLIC KEY") {
      return { key: await importSPKI(material, alg) };
    }
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      `Unsupported PEM type "${label}". Use a public key, certificate, or JWK.`,
    );
  } catch {
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      "PEM key material is malformed or does not match the token algorithm.",
    );
  }
}

async function importJsonKey(
  material: string,
  alg: SupportedAlgorithm,
  kid: string | undefined,
): Promise<{ key: Uint8Array | CryptoKey } | VerifyJwtResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(material);
  } catch {
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      "Key material looks like JSON but is not valid JSON.",
    );
  }

  const selected = selectJwk(parsed, alg, kid);
  if ("code" in selected) {
    return selected;
  }

  const jwk = selected.jwk;
  if (typeof jwk.use === "string" && jwk.use !== "sig") {
    return verifyResult(
      "KEY_TYPE_MISMATCH",
      alg,
      `JWK use is "${jwk.use}", not signature verification.`,
    );
  }

  if (typeof jwk.alg === "string" && jwk.alg !== alg) {
    return verifyResult(
      "KEY_TYPE_MISMATCH",
      alg,
      `JWK alg "${jwk.alg}" does not match token alg ${alg}.`,
    );
  }

  const expectedKty = expectedJwkKty(alg);
  if (jwk.kty !== expectedKty) {
    return verifyResult(
      "KEY_TYPE_MISMATCH",
      alg,
      `JWK kty "${jwk.kty ?? "(missing)"}" does not match ${alg}.`,
    );
  }

  try {
    const key = await importJWK(jwk, alg);
    return { key };
  } catch {
    return verifyResult(
      "MALFORMED_KEY",
      alg,
      "JWK is malformed or cannot be used with this algorithm.",
    );
  }
}

function selectJwk(
  parsed: unknown,
  alg: SupportedAlgorithm,
  kid: string | undefined,
): { jwk: JWK } | VerifyJwtResult {
  if (isJwks(parsed)) {
    let candidates = parsed.keys.filter(isJwk);
    if (kid) {
      const byKid = candidates.filter((key) => key.kid === kid);
      if (byKid.length === 0) {
        return verifyResult(
          "MALFORMED_KEY",
          alg,
          `No JWK matches kid "${kid}".`,
        );
      }
      candidates = byKid;
    }
    if (candidates.length === 0) {
      return verifyResult("MALFORMED_KEY", alg, "JWKS does not contain any keys.");
    }
    if (candidates.length > 1) {
      return verifyResult(
        "MALFORMED_KEY",
        alg,
        "Multiple JWKs could apply. Paste a single JWK or use a token kid that matches one key.",
      );
    }
    return { jwk: candidates[0] };
  }

  if (isJwk(parsed)) {
    if (
      kid &&
      typeof parsed.kid === "string" &&
      parsed.kid !== kid
    ) {
      return verifyResult(
        "MALFORMED_KEY",
        alg,
        `JWK kid "${parsed.kid}" does not match token kid "${kid}".`,
      );
    }
    return { jwk: parsed };
  }

  return verifyResult(
    "MALFORMED_KEY",
    alg,
    "Key material is not a JWK or JWKS.",
  );
}

function mapVerifyError(error: unknown, alg: SupportedAlgorithm): VerifyJwtResult {
  if (error instanceof errors.JWSSignatureVerificationFailed) {
    return verifyResult("INVALID_SIGNATURE", alg, "Invalid signature.");
  }
  if (error instanceof errors.JOSEAlgNotAllowed) {
    return verifyResult(
      "UNSUPPORTED_ALGORITHM",
      alg,
      `Signing algorithm "${alg}" is not allowed.`,
    );
  }
  if (error instanceof errors.JOSENotSupported) {
    return verifyResult(
      "UNSUPPORTED_ALGORITHM",
      alg,
      `Signing algorithm "${alg}" is not supported.`,
    );
  }
  if (error instanceof errors.JWSInvalid) {
    return verifyResult(
      "INVALID_SIGNATURE",
      alg,
      "Invalid signature.",
    );
  }
  return verifyResult(
    "INVALID_SIGNATURE",
    alg,
    "Invalid signature.",
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJwk(value: unknown): value is JWK {
  return isRecord(value) && typeof value.kty === "string";
}

function isJwks(value: unknown): value is { keys: unknown[] } {
  return isRecord(value) && Array.isArray(value.keys);
}
