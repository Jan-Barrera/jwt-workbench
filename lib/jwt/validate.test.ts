import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { validateJwt } from "./validate";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const NOW = new Date("2026-01-15T12:00:00.000Z");

function check(id: string, checks: ReturnType<typeof validateJwt>["checks"]) {
  const row = checks.find((c) => c.id === id);
  assert.ok(row, `missing check ${id}`);
  return row;
}

describe("validateJwt", () => {
  it("reports structure failure without hiding other check rows", () => {
    const { checks } = validateJwt("not.a.valid.jwt", { now: NOW });
    assert.equal(check("structure", checks).outcome, "fail");
    assert.equal(check("expiration", checks).outcome, "skipped");
    assert.equal(check("signature", checks).outcome, "not_verified");
    assert.equal(checks.length, 6);
  });

  it("passes structure for a decodable JWT", () => {
    const { checks } = validateJwt(SAMPLE_JWT, { now: NOW });
    assert.equal(check("structure", checks).outcome, "pass");
  });

  it("marks expired exp as fail", () => {
    const payload = Buffer.from(JSON.stringify({ exp: 1 }), "utf8").toString(
      "base64url",
    );
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    const { checks } = validateJwt(jwt, { now: NOW });
    assert.equal(check("expiration", checks).outcome, "fail");
  });

  it("applies clock tolerance to exp", () => {
    const exp = Math.floor(NOW.getTime() / 1000) - 30;
    const payload = Buffer.from(JSON.stringify({ exp }), "utf8")
      .toString("base64url");
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;

    const strict = validateJwt(jwt, { now: NOW, clockToleranceSeconds: 0 });
    assert.equal(check("expiration", strict.checks).outcome, "fail");

    const lenient = validateJwt(jwt, { now: NOW, clockToleranceSeconds: 60 });
    assert.equal(check("expiration", lenient.checks).outcome, "pass");
  });

  it("marks future nbf as fail", () => {
    const future = Math.floor(NOW.getTime() / 1000) + 3600;
    const payload = Buffer.from(JSON.stringify({ nbf: future }), "utf8")
      .toString("base64url");
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    const { checks } = validateJwt(jwt, { now: NOW });
    assert.equal(check("not_before", checks).outcome, "fail");
  });

  it("reports audience mismatch with expected and actual", () => {
    const payload = Buffer.from(
      JSON.stringify({ aud: "payments-api" }),
      "utf8",
    ).toString("base64url");
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    const { checks } = validateJwt(jwt, {
      now: NOW,
      expectedAudience: "orders-api",
    });
    const aud = check("audience", checks);
    assert.equal(aud.outcome, "fail");
    assert.equal(aud.expected, "orders-api");
    assert.equal(aud.actual, "payments-api");
  });

  it("accepts audience when expected value is in aud array", () => {
    const payload = Buffer.from(
      JSON.stringify({ aud: ["payments-api", "orders-api"] }),
      "utf8",
    ).toString("base64url");
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    const { checks } = validateJwt(jwt, {
      now: NOW,
      expectedAudience: "orders-api",
    });
    assert.equal(check("audience", checks).outcome, "pass");
  });

  it("shows signature as not verified when no material supplied", () => {
    const { checks } = validateJwt(SAMPLE_JWT, { now: NOW });
    const sig = check("signature", checks);
    assert.equal(sig.outcome, "not_verified");
    assert.match(sig.message, /not verified|No verification/i);
  });

  it("integrates supplied signature verification result", () => {
    const { checks } = validateJwt(SAMPLE_JWT, {
      now: NOW,
      signature: { status: "pass" },
    });
    assert.equal(check("signature", checks).outcome, "pass");

    const failed = validateJwt(SAMPLE_JWT, {
      now: NOW,
      signature: { status: "fail", message: "Invalid signature" },
    });
    assert.equal(check("signature", failed.checks).outcome, "fail");
  });
});
