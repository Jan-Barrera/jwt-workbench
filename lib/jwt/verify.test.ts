import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import {
  SignJWT,
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
} from "jose";

import { signatureCheck } from "./validate";
import {
  toSignatureVerificationResult,
  verifyJwt,
} from "./verify";

const HS256_SECRET = "your-256-bit-secret";
const HS256_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

function encodeSegment(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function replaceSegment(token: string, index: 0 | 1 | 2, value: string): string {
  const parts = token.split(".");
  parts[index] = value;
  return parts.join(".");
}

describe("verifyJwt", () => {
  let rsa: Awaited<ReturnType<typeof generateKeyPair>>;
  let rsaSpki: string;
  let rsaJwk: Record<string, unknown>;
  let rsaToken: string;

  before(async () => {
    rsa = await generateKeyPair("RS256", { extractable: true });
    rsaSpki = await exportSPKI(rsa.publicKey);
    rsaJwk = (await exportJWK(rsa.publicKey)) as Record<string, unknown>;
    rsaToken = await new SignJWT({ sub: "rsa" })
      .setProtectedHeader({ alg: "RS256", kid: "rsa-1", typ: "JWT" })
      .sign(rsa.privateKey);
  });

  it("verifies a Bearer-prefixed HS256 token", async () => {
    const result = await verifyJwt(`Bearer ${HS256_JWT}`, {
      keyMaterial: HS256_SECRET,
    });
    assert.equal(result.code, "PASS");
  });

  it("verifies HS256 using an oct JWK", async () => {
    const jwk = {
      kty: "oct",
      k: Buffer.from(HS256_SECRET, "utf8").toString("base64url"),
      alg: "HS256",
    };
    const result = await verifyJwt(HS256_JWT, {
      keyMaterial: JSON.stringify(jwk),
    });
    assert.equal(result.code, "PASS");
  });

  it("does not report an invalid signature when JWKS has no matching kid", async () => {
    const jwks = {
      keys: [{ ...rsaJwk, kid: "other-key" }],
    };
    const result = await verifyJwt(rsaToken, {
      keyMaterial: JSON.stringify(jwks),
    });
    assert.equal(result.code, "MALFORMED_KEY");
    assert.match(result.message, /kid/i);
  });

  it("selects a matching JWK from a JWKS by kid", async () => {
    const other = await generateKeyPair("RS256", { extractable: true });
    const otherJwk = await exportJWK(other.publicKey);
    const jwks = {
      keys: [
        { ...otherJwk, kid: "other" },
        { ...rsaJwk, kid: "rsa-1", use: "sig", alg: "RS256" },
      ],
    };

    const result = await verifyJwt(rsaToken, {
      keyMaterial: JSON.stringify(jwks),
    });
    assert.equal(result.code, "PASS");
  });

  it("fails when the payload is modified", async () => {
    const tampered = replaceSegment(HS256_JWT, 1, encodeSegment({ sub: "hacked" }));
    const result = await verifyJwt(tampered, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "INVALID_SIGNATURE");
    assert.equal(result.ok, false);
  });

  it("fails when the header is modified", async () => {
    const tampered = replaceSegment(
      HS256_JWT,
      0,
      encodeSegment({ alg: "HS256", typ: "JWT", extra: true }),
    );
    const result = await verifyJwt(tampered, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "INVALID_SIGNATURE");
  });

  it("fails when the signature is modified", async () => {
    const tampered = `${HS256_JWT.slice(0, -2)}ab`;
    const result = await verifyJwt(tampered, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "INVALID_SIGNATURE");
  });

  it("fails with the wrong HMAC secret", async () => {
    const result = await verifyJwt(HS256_JWT, { keyMaterial: "wrong-secret" });
    assert.equal(result.code, "INVALID_SIGNATURE");
  });

  it("reports missing key instead of success", async () => {
    const result = await verifyJwt(HS256_JWT);
    assert.equal(result.code, "MISSING_KEY");
    assert.equal(result.ok, false);
    assert.match(result.message, /No verification key/i);

    const check = signatureCheck(toSignatureVerificationResult(result));
    assert.equal(check.outcome, "not_verified");
  });

  it("rejects the none algorithm", async () => {
    const token = `${encodeSegment({ alg: "none", typ: "JWT" })}.${encodeSegment({ sub: "1" })}.x`;
    const result = await verifyJwt(token, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "NONE_ALGORITHM");
    assert.equal(result.ok, false);

    const check = signatureCheck(toSignatureVerificationResult(result));
    assert.equal(check.outcome, "fail");
  });

  it("rejects unsupported algorithms without verifying", async () => {
    const token = `${encodeSegment({ alg: "HS1" })}.${encodeSegment({ sub: "1" })}.sig`;
    const result = await verifyJwt(token, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "UNSUPPORTED_ALGORITHM");
    assert.equal(result.algorithm, "HS1");
  });

  it("reports malformed JWK JSON distinctly from invalid signatures", async () => {
    const result = await verifyJwt(HS256_JWT, { keyMaterial: "{not-json" });
    assert.equal(result.code, "MALFORMED_KEY");
  });

  it("reports malformed PEM distinctly from invalid signatures", async () => {
    const result = await verifyJwt(rsaToken, {
      keyMaterial: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----",
    });
    assert.equal(result.code, "MALFORMED_KEY");
  });

  it("does not treat an RSA public key as an HMAC secret", async () => {
    const confused = await new SignJWT({ sub: "x" })
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode(rsaSpki));

    const auto = await verifyJwt(confused, { keyMaterial: rsaSpki });
    assert.equal(auto.code, "KEY_TYPE_MISMATCH");
    assert.equal(auto.ok, false);

    const forcedSecret = await verifyJwt(confused, {
      keyMaterial: rsaSpki,
      keyFormat: "secret",
    });
    assert.equal(forcedSecret.code, "KEY_TYPE_MISMATCH");
  });

  it("rejects a shared secret for RS256", async () => {
    const result = await verifyJwt(rsaToken, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "KEY_TYPE_MISMATCH");
  });

  it("rejects a JWK whose alg does not match the token", async () => {
    const result = await verifyJwt(rsaToken, {
      keyMaterial: JSON.stringify({ ...rsaJwk, alg: "RS512" }),
    });
    assert.equal(result.code, "KEY_TYPE_MISMATCH");
  });

  it("rejects private keys for verification", async () => {
    const pkcs8 = await exportPKCS8(rsa.privateKey);
    const result = await verifyJwt(rsaToken, { keyMaterial: pkcs8 });
    assert.equal(result.code, "MALFORMED_KEY");
    assert.match(result.message, /Private keys/i);
  });

  it("does not echo secrets in the result payload", async () => {
    const secret = "super-secret-value-xyz";
    const result = await verifyJwt(HS256_JWT, { keyMaterial: secret });
    assert.equal(JSON.stringify(result).includes(secret), false);
  });

  it("maps pass/fail so verification is not confused with decode success", async () => {
    const pass = signatureCheck(
      toSignatureVerificationResult(
        await verifyJwt(HS256_JWT, { keyMaterial: HS256_SECRET }),
      ),
    );
    assert.equal(pass.outcome, "pass");

    const fail = signatureCheck(
      toSignatureVerificationResult(
        await verifyJwt(HS256_JWT, { keyMaterial: "nope" }),
      ),
    );
    assert.equal(fail.outcome, "fail");
  });
});
