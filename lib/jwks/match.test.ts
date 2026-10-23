import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { JwksKeyEntry } from "./types";
import { jwkCompatibility, matchKeysByKid } from "./match";

function entry(
  index: number,
  partial: Partial<JwksKeyEntry> & { kty: string },
): JwksKeyEntry {
  return {
    index,
    jwk: { kty: partial.kty, kid: partial.kid ?? undefined },
    kid: partial.kid ?? null,
    kty: partial.kty,
    use: partial.use ?? null,
    alg: partial.alg ?? null,
  };
}

describe("matchKeysByKid", () => {
  const keys = [
    entry(0, { kty: "RSA", kid: "one" }),
    entry(1, { kty: "RSA", kid: "two" }),
  ];

  it("reports missing token kid", () => {
    assert.equal(matchKeysByKid(keys, null).code, "NO_TOKEN_KID");
  });

  it("finds a single match", () => {
    const match = matchKeysByKid(keys, "two");
    assert.equal(match.code, "SINGLE_MATCH");
    assert.deepEqual(match.matchedIndices, [1]);
  });

  it("reports no match", () => {
    assert.equal(matchKeysByKid(keys, "missing").code, "NO_MATCH");
  });
});

describe("jwkCompatibility", () => {
  it("flags non-sig use and alg mismatch", () => {
    const enc = jwkCompatibility(
      { kty: "RSA", use: "enc", alg: "RS256" },
      "RS256",
    );
    assert.equal(enc.compatible, false);
    assert.match(enc.reasons.join(" "), /use/i);

    const alg = jwkCompatibility({ kty: "RSA", alg: "RS384" }, "RS256");
    assert.equal(alg.compatible, false);
  });

  it("accepts a compatible RSA key", () => {
    const ok = jwkCompatibility({ kty: "RSA", use: "sig" }, "RS256");
    assert.equal(ok.compatible, true);
  });
});
