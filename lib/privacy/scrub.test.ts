import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  REDACTED,
  formatErrorForReporting,
  looksLikeJwt,
  scrubSensitiveText,
  scrubSensitiveValue,
} from "./scrub";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

const SAMPLE_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AH
-----END RSA PRIVATE KEY-----`;

describe("looksLikeJwt", () => {
  it("accepts compact JWTs", () => {
    assert.equal(looksLikeJwt(SAMPLE_JWT), true);
    assert.equal(looksLikeJwt(`Bearer ${SAMPLE_JWT}`), true);
  });

  it("rejects malformed strings", () => {
    assert.equal(looksLikeJwt("not.a.jwt"), false);
    assert.equal(looksLikeJwt("two.parts"), false);
    assert.equal(looksLikeJwt(""), false);
  });
});

describe("scrubSensitiveText", () => {
  it("redacts JWTs and Bearer prefixes", () => {
    const input = `Token failed: ${SAMPLE_JWT} and Bearer ${SAMPLE_JWT}`;
    const out = scrubSensitiveText(input);
    assert.equal(out.includes(SAMPLE_JWT), false);
    assert.equal(out.includes("Bearer"), false);
    assert.match(out, new RegExp(REDACTED, "g"));
  });

  it("redacts private PEM blocks", () => {
    const out = scrubSensitiveText(`key=${SAMPLE_PEM}`);
    assert.equal(out.includes("RSA PRIVATE KEY"), false);
    assert.match(out, /\[REDACTED\]/);
  });

  it("redacts private JWK scalar fields in JSON text", () => {
    const input = '{"kty":"RSA","d":"super-secret"}';
    const out = scrubSensitiveText(input);
    assert.equal(out.includes("super-secret"), false);
    assert.match(out, /"d"\s*:\s*"\[REDACTED\]"/);
  });
});

describe("scrubSensitiveValue", () => {
  it("redacts known secret field names in objects", () => {
    const out = scrubSensitiveValue({
      access_token: SAMPLE_JWT,
      nested: { client_secret: "abc" },
      safe: "hello",
    }) as Record<string, unknown>;

    assert.equal(out.access_token, REDACTED);
    assert.deepEqual(out.nested, { client_secret: REDACTED });
    assert.equal(out.safe, "hello");
  });

  it("scrubs Error instances", () => {
    const error = new Error(`verify failed for ${SAMPLE_JWT}`);
    const out = scrubSensitiveValue(error) as {
      message: string;
    };
    assert.equal(out.message.includes(SAMPLE_JWT), false);
    assert.match(out.message, /\[REDACTED\]/);
  });
});

describe("formatErrorForReporting", () => {
  it("returns scrubbed strings for Error and unknown values", () => {
    assert.match(
      formatErrorForReporting(new Error(`bad ${SAMPLE_JWT}`)),
      /\[REDACTED\]/,
    );
    assert.match(formatErrorForReporting(`raw ${SAMPLE_JWT}`), /\[REDACTED\]/);
  });
});
