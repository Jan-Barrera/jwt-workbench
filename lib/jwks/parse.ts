import type { JWK } from "jose";

import type { JwksKeyEntry, JwksParseResult, ParsedJwks } from "./types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJwk(value: unknown): value is JWK {
  return isRecord(value) && typeof value.kty === "string";
}

export function parseJwksText(text: string): JwksParseResult {
  const trimmed = text.trim();
  if (!trimmed) {
    return {
      code: "INVALID_JSON",
      message: "Paste JWKS JSON or fetch from a URL.",
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { code: "INVALID_JSON", message: "JWKS text is not valid JSON." };
  }

  return parseJwksValue(parsed);
}

export function parseJwksValue(parsed: unknown): JwksParseResult {
  if (!isRecord(parsed) || !Array.isArray(parsed.keys)) {
    return {
      code: "INVALID_SHAPE",
      message: 'JWKS must be a JSON object with a "keys" array.',
    };
  }

  const keys: JwksKeyEntry[] = [];
  for (let index = 0; index < parsed.keys.length; index += 1) {
    const entry = parsed.keys[index];
    if (!isJwk(entry)) {
      continue;
    }
    keys.push(summarizeKey(index, entry));
  }

  if (keys.length === 0) {
    return {
      code: "NO_KEYS",
      message: "JWKS does not contain any keys with a kty field.",
    };
  }

  return { code: "OK", keys } satisfies ParsedJwks;
}

function summarizeKey(index: number, jwk: JWK): JwksKeyEntry {
  return {
    index,
    jwk,
    kid: typeof jwk.kid === "string" ? jwk.kid : null,
    kty: jwk.kty as string,
    use: typeof jwk.use === "string" ? jwk.use : null,
    alg: typeof jwk.alg === "string" ? jwk.alg : null,
  };
}

export function serializeJwk(jwk: JWK): string {
  return JSON.stringify(jwk, null, 2);
}
