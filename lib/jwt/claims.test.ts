import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { inspectPayloadClaims } from "./claims";

const NOW = new Date("2026-01-15T12:00:00.000Z");

describe("inspectPayloadClaims", () => {
  it("lists registered claims before custom claims", () => {
    const rows = inspectPayloadClaims(
      { custom: true, sub: "user-1", iss: "auth" },
      NOW,
    );
    assert.deepEqual(rows.map((r) => r.name), ["iss", "sub", "custom"]);
  });

  it("keeps numeric timestamp in raw value and adds interpreted dates", () => {
    const exp = 1516239022;
    const rows = inspectPayloadClaims({ exp }, NOW);
    const expRow = rows.find((r) => r.name === "exp");
    assert.ok(expRow);
    assert.equal(expRow.rawValue, String(exp));
    assert.match(expRow.interpretedValue ?? "", /Local:/);
    assert.match(expRow.interpretedValue ?? "", /UTC:/);
  });

  it("marks expired tokens", () => {
    const rows = inspectPayloadClaims({ exp: 1 }, NOW);
    const expRow = rows.find((r) => r.name === "exp");
    assert.equal(expRow?.status, "expired");
    assert.equal(expRow?.statusLabel, "Expired");
  });

  it("marks future exp as not expired", () => {
    const future = Math.floor(NOW.getTime() / 1000) + 3600;
    const rows = inspectPayloadClaims({ exp: future }, NOW);
    const expRow = rows.find((r) => r.name === "exp");
    assert.equal(expRow?.status, "active");
    assert.equal(expRow?.statusLabel, "Not expired");
  });

  it("marks future nbf as not yet valid", () => {
    const future = Math.floor(NOW.getTime() / 1000) + 3600;
    const rows = inspectPayloadClaims({ nbf: future }, NOW);
    const nbfRow = rows.find((r) => r.name === "nbf");
    assert.equal(nbfRow?.status, "not_yet_valid");
    assert.equal(nbfRow?.statusLabel, "Not yet valid");
  });

  it("interprets iat as dates without validity status", () => {
    const iat = Math.floor(NOW.getTime() / 1000) - 60;
    const rows = inspectPayloadClaims({ iat }, NOW);
    const iatRow = rows.find((r) => r.name === "iat");
    assert.equal(iatRow?.rawValue, String(iat));
    assert.match(iatRow?.interpretedValue ?? "", /Local:/);
    assert.equal(iatRow?.status, null);
    assert.equal(iatRow?.statusLabel, null);
  });

  it("includes friendly names and descriptions for registered claims", () => {
    const rows = inspectPayloadClaims({ iss: "https://issuer.example" }, NOW);
    const iss = rows.find((r) => r.name === "iss");
    assert.equal(iss?.friendlyName, "Issuer");
    assert.match(iss?.description ?? "", /issued/i);
  });

  it("handles aud as string or array", () => {
    const single = inspectPayloadClaims({ aud: "api" }, NOW)[0];
    assert.equal(single.interpretedValue, "Audience: api");

    const multi = inspectPayloadClaims({ aud: ["a", "b"] }, NOW)[0];
    assert.equal(multi.interpretedValue, "Audiences: a, b");
  });

  it("leaves custom claims unchanged", () => {
    const rows = inspectPayloadClaims({ role: "admin", count: 3 }, NOW);
    const role = rows.find((r) => r.name === "role");
    assert.equal(role?.rawValue, "admin");
    assert.equal(role?.friendlyName, null);
    assert.equal(role?.interpretedValue, null);
  });

  it("returns empty list for non-object payloads", () => {
    assert.deepEqual(inspectPayloadClaims("jwt", NOW), []);
    assert.deepEqual(inspectPayloadClaims(null, NOW), []);
  });
});
