import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { validateJwksFetchUrl } from "./url";

describe("validateJwksFetchUrl", () => {
  it("accepts public https URLs", () => {
    const result = validateJwksFetchUrl(
      "https://issuer.example/.well-known/jwks.json",
    );
    assert.equal(result.code, "OK");
  });

  it("blocks loopback and private hosts", () => {
    assert.equal(
      validateJwksFetchUrl("http://127.0.0.1/jwks").code,
      "BLOCKED_HOST",
    );
    assert.equal(
      validateJwksFetchUrl("http://192.168.1.10/jwks").code,
      "BLOCKED_HOST",
    );
  });

  it("rejects non-http schemes", () => {
    assert.equal(
      validateJwksFetchUrl("file:///etc/passwd").code,
      "INVALID_URL",
    );
  });
});
