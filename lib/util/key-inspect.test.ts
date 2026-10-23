import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { inspectKeyMaterial } from "./key-inspect";

const RSA_JWK_PUBLIC = {
  kty: "RSA",
  kid: "test-rsa",
  use: "sig",
  alg: "RS256",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRkwHT9kT0C7z4K8R4E1lF2h0YQ2X0YQ",
  e: "AQAB",
  d: "must-not-appear",
};

describe("inspectKeyMaterial", () => {
  it("inspects a public JWK and omits private fields", async () => {
    const result = await inspectKeyMaterial(JSON.stringify(RSA_JWK_PUBLIC));
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.equal(result.format, "jwk");
    assert.equal(result.entries.length, 1);
    const entry = result.entries[0];
    assert.equal(entry.kty, "RSA");
    assert.ok(entry.fields.some((field) => field.name === "n"));
    assert.ok(!entry.fields.some((field) => field.name === "d"));
    assert.ok(!entry.safeJson.includes("must-not-appear"));
    assert.ok(entry.warnings.some((warning) => /Private field "d"/.test(warning)));
  });

  it("inspects a JWKS document", async () => {
    const jwks = { keys: [RSA_JWK_PUBLIC, { kty: "EC", crv: "P-256", x: "abc", y: "def" }] };
    const result = await inspectKeyMaterial(JSON.stringify(jwks));
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.format, "jwks");
    assert.equal(result.entries.length, 2);
  });

  it("rejects private PEM", async () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M
-----END RSA PRIVATE KEY-----`;
    const result = await inspectKeyMaterial(pem);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.match(result.message, /Private key/i);
  });

  it("rejects unrecognized input", async () => {
    const result = await inspectKeyMaterial("plain text");
    assert.equal(result.ok, false);
  });
});
