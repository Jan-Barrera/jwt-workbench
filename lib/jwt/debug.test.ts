import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildJwtDebugReport } from "./debug";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const NOW = new Date("2026-01-15T12:00:00.000Z");

function finding(id: string, report: ReturnType<typeof buildJwtDebugReport>) {
  const row = report.findings.find((f) => f.id === id);
  assert.ok(row, `missing finding ${id}`);
  return row;
}

describe("buildJwtDebugReport", () => {
  it("includes structure failure and skipped claim checks for malformed tokens", () => {
    const report = buildJwtDebugReport("not.a.valid.jwt", { now: NOW });
    assert.equal(report.decode.ok, false);
    assert.equal(finding("structure", report).outcome, "fail");
    assert.equal(finding("expiration", report).outcome, "skipped");
    assert.equal(finding("signature", report).outcome, "not_verified");
    assert.equal(report.keyMatching, null);
  });

  it("reports header alg and decode-not-trust observation for valid JWTs", () => {
    const report = buildJwtDebugReport(SAMPLE_JWT, { now: NOW });
    assert.equal(report.decode.ok, true);
    assert.equal(report.algorithm, "HS256");
    assert.equal(finding("header.alg", report).actual, "HS256");
    assert.equal(finding("observation.decode_not_trust", report).outcome, "info");
    assert.equal(finding("signature", report).outcome, "not_verified");
  });

  it("separates validation failures from advisory observations", () => {
    const payload = Buffer.from(
      JSON.stringify({ aud: "payments-api" }),
      "utf8",
    ).toString("base64url");
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    const report = buildJwtDebugReport(jwt, {
      now: NOW,
      expectedAudience: "orders-api",
    });

    assert.equal(report.failures.length, 1);
    assert.equal(report.failures[0]?.id, "audience");
    assert.ok(report.observations.some((o) => o.id === "observation.decode_not_trust"));
    assert.ok(!report.observations.some((o) => o.id === "signature"));
  });

  it("incorporates JWKS kid matching when JWKS text is supplied", () => {
    const header = Buffer.from(
      JSON.stringify({ alg: "RS256", kid: "key-1" }),
      "utf8",
    ).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "user" }), "utf8")
      .toString("base64url");
    const jwt = `${header}.${payload}.sig`;
    const jwks = JSON.stringify({
      keys: [
        { kty: "RSA", kid: "key-1", alg: "RS256", n: "x", e: "AQAB" },
        { kty: "RSA", kid: "key-2", alg: "RS256", n: "y", e: "AQAB" },
      ],
    });

    const report = buildJwtDebugReport(jwt, { now: NOW, jwksText: jwks });
    assert.ok(report.keyMatching);
    assert.equal(report.keyMatching?.kidMatch?.code, "SINGLE_MATCH");
    assert.equal(finding("key_matching.kid", report).outcome, "info");
  });

  it("reports JWKS parse errors as key-matching failures", () => {
    const report = buildJwtDebugReport(SAMPLE_JWT, {
      now: NOW,
      jwksText: "{ not json",
    });
    assert.ok(report.keyMatching?.parseError);
    assert.equal(finding("key_matching.parse", report).outcome, "fail");
    assert.ok(report.failures.some((f) => f.id === "key_matching.parse"));
  });

  it("includes signature pass when verification result is supplied", () => {
    const report = buildJwtDebugReport(SAMPLE_JWT, {
      now: NOW,
      signature: { status: "pass", message: "Signature verified with HS256." },
    });
    assert.equal(finding("signature", report).outcome, "pass");
    assert.equal(report.failures.length, 0);
  });

  it("summarizes recognized claims for decodable payloads", () => {
    const report = buildJwtDebugReport(SAMPLE_JWT, { now: NOW });
    assert.ok(report.claims.some((c) => c.name === "sub"));
    assert.ok(report.claims.some((c) => c.name === "iat"));
  });

  it("warns when alg is none", () => {
    const header = Buffer.from(JSON.stringify({ alg: "none" }), "utf8")
      .toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "x" }), "utf8")
      .toString("base64url");
    const jwt = `${header}.${payload}.sig`;

    const report = buildJwtDebugReport(jwt, { now: NOW });
    assert.equal(report.decode.ok, true);
    assert.equal(finding("observation.alg_none", report).severity, "warning");
  });
});
