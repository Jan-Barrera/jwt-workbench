import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parseJwksText, serializeJwk } from "./parse";

describe("parseJwksText", () => {
  it("parses a valid JWKS", () => {
    const result = parseJwksText(
      JSON.stringify({
        keys: [
          { kty: "RSA", kid: "a", use: "sig", alg: "RS256", n: "x", e: "AQAB" },
          { kty: "EC", kid: "b" },
        ],
      }),
    );
    assert.equal(result.code, "OK");
    if (result.code !== "OK") return;
    assert.equal(result.keys.length, 2);
    assert.equal(result.keys[0].kid, "a");
    assert.equal(result.keys[0].kty, "RSA");
  });

  it("rejects invalid JSON and shape", () => {
    assert.equal(parseJwksText("{").code, "INVALID_JSON");
    assert.equal(parseJwksText('{"keys":"nope"}').code, "INVALID_SHAPE");
    assert.equal(parseJwksText('{"keys":[]}').code, "NO_KEYS");
  });

  it("serializes a single JWK", () => {
    const jwk = { kty: "RSA", kid: "1" };
    assert.match(serializeJwk(jwk), /"kid": "1"/);
  });
});
