import type { JWK } from "jose";

import { isHmacAlgorithm, isSupportedAlgorithm } from "@/lib/jwt/verify";

import type {
  JwkCompatibility,
  JwksKeyEntry,
  KidMatchResult,
} from "./types";

export function matchKeysByKid(
  keys: JwksKeyEntry[],
  tokenKid: string | null | undefined,
): KidMatchResult {
  if (!tokenKid) {
    return {
      code: "NO_TOKEN_KID",
      message:
        "JWT header has no kid. Pick a key explicitly for verification.",
      matchedIndices: [],
    };
  }

  const withKid = keys.filter((entry) => entry.kid !== null);
  if (withKid.length === 0) {
    return {
      code: "NO_JWKS_KID",
      message:
        "No keys in this JWKS declare a kid. Pick a key explicitly for verification.",
      matchedIndices: [],
    };
  }

  const matchedIndices = keys
    .filter((entry) => entry.kid === tokenKid)
    .map((entry) => entry.index);

  if (matchedIndices.length === 0) {
    return {
      code: "NO_MATCH",
      message: `No key in the JWKS matches token kid "${tokenKid}".`,
      matchedIndices: [],
    };
  }

  if (matchedIndices.length === 1) {
    return {
      code: "SINGLE_MATCH",
      message: `One key matches token kid "${tokenKid}".`,
      matchedIndices,
    };
  }

  return {
    code: "MULTIPLE_MATCHES",
    message: `Multiple keys match token kid "${tokenKid}". Select one explicitly.`,
    matchedIndices,
  };
}

export function jwkCompatibility(
  jwk: JWK,
  tokenAlg: string | null | undefined,
): JwkCompatibility {
  const reasons: string[] = [];

  if (typeof jwk.use === "string" && jwk.use !== "sig") {
    reasons.push(`use is "${jwk.use}", not signature verification (sig).`);
  }

  if (!tokenAlg) {
    return {
      compatible: reasons.length === 0,
      reasons,
    };
  }

  if (tokenAlg === "none") {
    reasons.push('Token uses the "none" algorithm.');
    return { compatible: false, reasons };
  }

  if (!isSupportedAlgorithm(tokenAlg)) {
    reasons.push(`Token algorithm "${tokenAlg}" is not supported here.`);
    return { compatible: false, reasons };
  }

  if (typeof jwk.alg === "string" && jwk.alg !== tokenAlg) {
    reasons.push(`JWK alg "${jwk.alg}" does not match token alg ${tokenAlg}.`);
  }

  const expectedKty = expectedJwkKty(tokenAlg);
  if (jwk.kty !== expectedKty) {
    reasons.push(
      `JWK kty "${jwk.kty ?? "(missing)"}" does not match ${tokenAlg} (expected ${expectedKty}).`,
    );
  }

  return {
    compatible: reasons.length === 0,
    reasons,
  };
}

function expectedJwkKty(alg: string): JWK["kty"] {
  if (isHmacAlgorithm(alg)) return "oct";
  if (alg.startsWith("RS") || alg.startsWith("PS")) return "RSA";
  if (alg.startsWith("ES")) return "EC";
  return "OKP";
}

export function isKidHighlight(
  entryIndex: number,
  match: KidMatchResult,
): boolean {
  return match.matchedIndices.includes(entryIndex);
}
