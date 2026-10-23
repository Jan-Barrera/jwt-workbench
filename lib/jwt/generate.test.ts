import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import { decodeJwt } from "./decode";
import {
  buildHeaderObject,
  buildPayloadFromFields,
  createLocalSigningMaterial,
  generateJwt,
  parseJsonObject,
} from "./generate";
import { verifyJwt } from "./verify";

describe("generateJwt", () => {
  let rsaPrivate: string;
  let rsaPublic: string;

  before(async () => {
    const material = await createLocalSigningMaterial("RS256");
    assert.equal(material.ok, true);
    if (!material.ok) return;
    rsaPrivate = material.privateKeyMaterial;
    rsaPublic = material.publicKeyMaterial;
  });

  it("signs an HS256 token that decodes and verifies", async () => {
    const secret = "your-256-bit-secret";
    const header = buildHeaderObject("HS256", { kid: "test" });
    const payloadResult = buildPayloadFromFields({
      sub: "1234567890",
      iat: "1516239022",
    });
    assert.equal(payloadResult.ok, true);
    if (!payloadResult.ok) return;

    const signed = await generateJwt({
      algorithm: "HS256",
      header,
      payload: payloadResult.payload,
      keyMaterial: secret,
      keyFormat: "secret",
    });
    assert.equal(signed.ok, true);
    if (!signed.ok) return;

    const decoded = decodeJwt(signed.token);
    assert.equal(decoded.ok, true);
    if (!decoded.ok) return;
    assert.equal((decoded.payload as { sub?: string }).sub, "1234567890");

    const verified = await verifyJwt(signed.token, {
      keyMaterial: secret,
      keyFormat: "secret",
    });
    assert.equal(verified.ok, true);
    assert.equal(verified.code, "PASS");
  });

  it("signs RS256 with a generated private key and verifies with public PEM", async () => {
    const header = buildHeaderObject("RS256", {});
    const payloadResult = buildPayloadFromFields({ sub: "rsa-user" });
    assert.equal(payloadResult.ok, true);
    if (!payloadResult.ok) return;

    const signed = await generateJwt({
      algorithm: "RS256",
      header,
      payload: payloadResult.payload,
      keyMaterial: rsaPrivate,
      keyFormat: "pem",
    });
    assert.equal(signed.ok, true);
    if (!signed.ok) return;

    const verified = await verifyJwt(signed.token, {
      keyMaterial: rsaPublic,
      keyFormat: "pem",
    });
    assert.equal(verified.code, "PASS");
  });

  it("rejects invalid payload JSON", () => {
    const parsed = parseJsonObject("{not json", "Payload");
    assert.equal(parsed.ok, false);
    if (parsed.ok) return;
    assert.equal(parsed.code, "INVALID_PAYLOAD");
  });

  it("rejects non-numeric exp in field builder", () => {
    const result = buildPayloadFromFields({ exp: "soon" });
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.code, "INVALID_CLAIM_VALUE");
  });

  it("requires signing key material", async () => {
    const signed = await generateJwt({
      algorithm: "HS256",
      header: buildHeaderObject("HS256", {}),
      payload: { sub: "x" },
      keyMaterial: "",
    });
    assert.equal(signed.ok, false);
    if (signed.ok) return;
    assert.equal(signed.code, "MISSING_KEY");
  });
});
