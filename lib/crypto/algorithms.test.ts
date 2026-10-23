import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  SUPPORTED_ALGORITHMS,
  expectedJwkKty,
  headerAlgorithmLabel,
  headerAlgorithmsMatch,
  isHmacAlgorithm,
  isSupportedAlgorithm,
  toJoseAlgorithm,
} from "./algorithms";

describe("lib/crypto/algorithms", () => {
  it("lists all supported signing algorithms", () => {
    assert.ok(SUPPORTED_ALGORITHMS.length >= 14);
    assert.equal(isSupportedAlgorithm("HS256"), true);
    assert.equal(isSupportedAlgorithm("none"), false);
  });

  it("classifies HMAC algorithms", () => {
    assert.equal(isHmacAlgorithm("HS256"), true);
    assert.equal(isHmacAlgorithm("RS256"), false);
  });

  it("maps Ed25519 to EdDSA for jose", () => {
    assert.equal(toJoseAlgorithm("Ed25519"), "EdDSA");
    assert.equal(headerAlgorithmLabel("Ed25519"), "EdDSA");
    assert.equal(headerAlgorithmsMatch("EdDSA", "Ed25519"), true);
  });

  it("maps expected JWK key types", () => {
    assert.equal(expectedJwkKty("HS256"), "oct");
    assert.equal(expectedJwkKty("RS256"), "RSA");
    assert.equal(expectedJwkKty("ES256"), "EC");
    assert.equal(expectedJwkKty("EdDSA"), "OKP");
  });
});
