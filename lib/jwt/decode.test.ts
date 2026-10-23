import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { decodeJwt, normalizeJwtInput } from "./decode";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

describe("normalizeJwtInput", () => {
  it("strips Bearer prefix", () => {
    assert.equal(normalizeJwtInput(`Bearer ${SAMPLE_JWT}`), SAMPLE_JWT);
  });

  it("strips Bearer prefix case-insensitively", () => {
    assert.equal(normalizeJwtInput(`bearer ${SAMPLE_JWT}`), SAMPLE_JWT);
  });

  it("trims whitespace", () => {
    assert.equal(normalizeJwtInput(`  ${SAMPLE_JWT}  `), SAMPLE_JWT);
  });
});

describe("decodeJwt", () => {
  it("decodes a valid JWT", () => {
    const result = decodeJwt(SAMPLE_JWT);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.deepEqual(result.header, { alg: "HS256", typ: "JWT" });
    const payload = result.payload as Record<string, unknown>;
    assert.equal(payload.sub, "1234567890");
    assert.equal(payload.name, "John Doe");
    assert.equal(payload.iat, 1516239022);
    assert.match(result.segments.signature, /^[A-Za-z0-9_-]+$/);
  });

  it("rejects malformed structure", () => {
    const result = decodeJwt("only.two");
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.code, "MALFORMED_STRUCTURE");
  });

  it("rejects invalid base64 in header", () => {
    const result = decodeJwt(`!!!.${SAMPLE_JWT.split(".")[1]}.sig`);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.code, "INVALID_BASE64");
    assert.equal(result.part, "header");
  });

  it("rejects invalid JSON in payload", () => {
    const badPayload = Buffer.from("not-json", "utf8").toString("base64url");
    const result = decodeJwt(
      `${SAMPLE_JWT.split(".")[0]}.${badPayload}.${SAMPLE_JWT.split(".")[2]}`,
    );
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.code, "INVALID_JSON");
    assert.equal(result.part, "payload");
  });
});
