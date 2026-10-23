import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { decodeBase64Url, encodeBase64Url } from "./base64url";

describe("encodeBase64Url", () => {
  it("encodes UTF-8 text", () => {
    const result = encodeBase64Url('{"alg":"HS256"}');
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.output, "eyJhbGciOiJIUzI1NiJ9");
  });

  it("rejects empty input", () => {
    const result = encodeBase64Url("");
    assert.equal(result.ok, false);
  });
});

describe("decodeBase64Url", () => {
  it("decodes to UTF-8 text", () => {
    const result = decodeBase64Url("eyJhbGciOiJIUzI1NiJ9");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.output, '{"alg":"HS256"}');
  });

  it("rejects malformed characters", () => {
    const result = decodeBase64Url("not valid!!!");
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.match(result.message, /Base64URL/i);
  });

  it("round-trips with encode", () => {
    const original = "Hello, JWT Workbench!";
    const encoded = encodeBase64Url(original);
    assert.equal(encoded.ok, true);
    if (!encoded.ok) return;
    const decoded = decodeBase64Url(encoded.output);
    assert.equal(decoded.ok, true);
    if (!decoded.ok) return;
    assert.equal(decoded.output, original);
  });
});
