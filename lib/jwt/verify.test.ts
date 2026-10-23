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

const HS384_SECRET = "s".repeat(48);
const HS512_SECRET = "s".repeat(64);

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

  let ec: Awaited<ReturnType<typeof generateKeyPair>>;
  let ecSpki: string;
  let ecToken: string;

  let pss: Awaited<ReturnType<typeof generateKeyPair>>;
  let pssSpki: string;
  let pssToken: string;

  let ed: Awaited<ReturnType<typeof generateKeyPair>>;
  let edToken: string;
  let edJwk: Record<string, unknown>;

  before(async () => {
    rsa = await generateKeyPair("RS256", { extractable: true });
    rsaSpki = await exportSPKI(rsa.publicKey);
    rsaJwk = (await exportJWK(rsa.publicKey)) as Record<string, unknown>;
    rsaToken = await new SignJWT({ sub: "rsa" })
      .setProtectedHeader({ alg: "RS256", kid: "rsa-1", typ: "JWT" })
      .sign(rsa.privateKey);

    ec = await generateKeyPair("ES256", { extractable: true });
    ecSpki = await exportSPKI(ec.publicKey);
    ecToken = await new SignJWT({ sub: "ec" })
      .setProtectedHeader({ alg: "ES256" })
      .sign(ec.privateKey);

    pss = await generateKeyPair("PS256", { extractable: true });
    pssSpki = await exportSPKI(pss.publicKey);
    pssToken = await new SignJWT({ sub: "pss" })
      .setProtectedHeader({ alg: "PS256" })
      .sign(pss.privateKey);

    ed = await generateKeyPair("EdDSA", { extractable: true });
    edJwk = (await exportJWK(ed.publicKey)) as Record<string, unknown>;
    edToken = await new SignJWT({ sub: "ed" })
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(ed.privateKey);
  });

  it("verifies the jwt.io HS256 test vector with a shared secret", async () => {
    const result = await verifyJwt(HS256_JWT, { keyMaterial: HS256_SECRET });
    assert.equal(result.code, "PASS");
    assert.equal(result.ok, true);
    assert.equal(result.algorithm, "HS256");
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

  it("verifies HS384 and HS512 with matching secrets", async () => {
    const hs384 = await new SignJWT({ sub: "384" })
      .setProtectedHeader({ alg: "HS384" })
      .sign(new TextEncoder().encode(HS384_SECRET));
    const hs512 = await new SignJWT({ sub: "512" })
      .setProtectedHeader({ alg: "HS512" })
      .sign(new TextEncoder().encode(HS512_SECRET));

    assert.equal(
      (await verifyJwt(hs384, { keyMaterial: HS384_SECRET })).code,
      "PASS",
    );
    assert.equal(
      (await verifyJwt(hs512, { keyMaterial: HS512_SECRET })).code,
      "PASS",
    );
  });

  it("verifies RS256 with a PEM public key and a JWK", async () => {
    const pem = await verifyJwt(rsaToken, { keyMaterial: rsaSpki });
    assert.equal(pem.code, "PASS");

    const jwk = await verifyJwt(rsaToken, {
      keyMaterial: JSON.stringify(rsaJwk),
    });
    assert.equal(jwk.code, "PASS");
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

  it("verifies ES256, PS256, and EdDSA with public material", async () => {
    assert.equal(
      (await verifyJwt(ecToken, { keyMaterial: ecSpki })).code,
      "PASS",
    );
    assert.equal(
      (await verifyJwt(pssToken, { keyMaterial: pssSpki })).code,
      "PASS",
    );
    assert.equal(
      (await verifyJwt(edToken, { keyMaterial: JSON.stringify(edJwk) })).code,
      "PASS",
    );
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
