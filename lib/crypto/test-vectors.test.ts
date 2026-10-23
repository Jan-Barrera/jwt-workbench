import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import {
  SignJWT,
  exportJWK,
  exportSPKI,
  generateKeyPair,
} from "jose";

import { verifyJwt } from "@/lib/jwt/verify";

import {
  SUPPORTED_ALGORITHMS,
  isHmacAlgorithm,
  toJoseAlgorithm,
  type SupportedAlgorithm,
} from "./algorithms";
import { STATIC_SIGNATURE_VECTORS } from "./test-vectors";

describe("signature test vectors", () => {
  const generated = new Map<
    SupportedAlgorithm,
    { token: string; verifyKey: string; keyFormat: "secret" | "pem" | "jwk" }
  >();

  before(async () => {
    for (const algorithm of SUPPORTED_ALGORITHMS) {
      if (isHmacAlgorithm(algorithm)) {
        const secret =
          algorithm === "HS256"
            ? "your-256-bit-secret"
            : "s".repeat(algorithm === "HS384" ? 48 : 64);
        const token = await new SignJWT({ sub: algorithm })
          .setProtectedHeader({ alg: algorithm })
          .sign(new TextEncoder().encode(secret));
        generated.set(algorithm, {
          token,
          verifyKey: secret,
          keyFormat: "secret",
        });
        continue;
      }

      const joseAlg = toJoseAlgorithm(algorithm);
      const pair = await generateKeyPair(joseAlg, { extractable: true });
      const publicSpki = await exportSPKI(pair.publicKey);
      const headerAlg =
        algorithm === "Ed25519" ? "EdDSA" : algorithm;
      const token = await new SignJWT({ sub: algorithm })
        .setProtectedHeader({ alg: headerAlg })
        .sign(pair.privateKey);

      generated.set(algorithm, {
        token,
        verifyKey: publicSpki,
        keyFormat: "pem",
      });
    }
  });

  it("verifies RS256 with a JWK instead of PEM", async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const publicJwk = await exportJWK(pair.publicKey);
    const token = await new SignJWT({ sub: "rs256-jwk" })
      .setProtectedHeader({ alg: "RS256" })
      .sign(pair.privateKey);
    const result = await verifyJwt(token, {
      keyMaterial: JSON.stringify(publicJwk),
      keyFormat: "jwk",
    });
    assert.equal(result.code, "PASS");
  });

  for (const vector of STATIC_SIGNATURE_VECTORS) {
    it(`verifies static vector ${vector.id}`, async () => {
      const result = await verifyJwt(vector.token, {
        keyMaterial: vector.keyMaterial,
        keyFormat: vector.keyFormat,
      });
      assert.equal(result.code, "PASS", result.message);
      assert.equal(result.algorithm, vector.algorithm);
    });
  }

  for (const algorithm of SUPPORTED_ALGORITHMS) {
    it(`verifies a generated ${algorithm} token`, async () => {
      const sample = generated.get(algorithm);
      assert.ok(sample, `missing generated vector for ${algorithm}`);
      const result = await verifyJwt(sample.token, {
        keyMaterial: sample.verifyKey,
        keyFormat: sample.keyFormat,
      });
      assert.equal(result.code, "PASS", `${algorithm}: ${result.message}`);
    });
  }
});
