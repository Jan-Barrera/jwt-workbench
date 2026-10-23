import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { compareJwts, filterChangedFields } from "./compare";

const TOKEN_A =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const TOKEN_B_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const TOKEN_B_PAYLOAD = Buffer.from(
  JSON.stringify({
    sub: "1234567890",
    name: "Jane Doe",
    iat: 1516239022,
    roles: ["user", "admin"],
    meta: { tier: "pro" },
  }),
  "utf8",
).toString("base64url");
const TOKEN_B = `${TOKEN_B_HEADER}.${TOKEN_B_PAYLOAD}.different-signature`;

describe("compareJwts", () => {
  it("reports unchanged fields for identical tokens", () => {
    const result = compareJwts(TOKEN_A, TOKEN_A);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.equal(result.signaturesDiffer, false);
    assert.equal(result.header.summary.unchanged, 2);
    assert.equal(result.payload.summary.unchanged, 3);
    assert.equal(result.header.summary.changed, 0);
    assert.equal(result.payload.summary.changed, 0);
  });

  it("detects changed, added, and removed payload fields", () => {
    const result = compareJwts(TOKEN_A, TOKEN_B);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.equal(result.signaturesDiffer, true);

    const payloadPaths = Object.fromEntries(
      result.payload.fields.map((field) => [field.path, field.kind]),
    );
    assert.equal(payloadPaths.name, "changed");
    assert.equal(payloadPaths["roles[0]"], "added");
    assert.equal(payloadPaths["roles[1]"], "added");
    assert.equal(payloadPaths["meta.tier"], "added");
    assert.equal(payloadPaths.sub, "unchanged");
    assert.equal(payloadPaths.iat, "unchanged");
  });

  it("compares nested objects and arrays deterministically", () => {
    const makeToken = (payload: unknown, signature = "sig") => {
      const header = Buffer.from(
        JSON.stringify({ alg: "HS256", typ: "JWT" }),
        "utf8",
      ).toString("base64url");
      const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
        "base64url",
      );
      return `${header}.${body}.${signature}`;
    };

    const left = makeToken({
      list: [1, 2],
      nested: { b: 2, a: 1 },
    });
    const right = makeToken({
      list: [1, 3],
      nested: { a: 1, b: 9 },
    });

    const result = compareJwts(left, right);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    const paths = result.payload.fields.map((field) => field.path);
    assert.deepEqual(paths, [...paths].sort());
    assert.equal(
      result.payload.fields.find((field) => field.path === "list[1]")?.kind,
      "changed",
    );
    assert.equal(
      result.payload.fields.find((field) => field.path === "nested.b")?.kind,
      "changed",
    );
  });

  it("does not treat signature differences as header or payload diffs", () => {
    const samePayloadDifferentSig = `${TOKEN_A.split(".")[0]}.${TOKEN_A.split(".")[1]}.other-signature`;
    const result = compareJwts(TOKEN_A, samePayloadDifferentSig);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.equal(result.signaturesDiffer, true);
    assert.equal(result.header.summary.changed, 0);
    assert.equal(result.payload.summary.changed, 0);
  });

  it("identifies when token A fails to decode", () => {
    const result = compareJwts("not-a-jwt", TOKEN_A);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.token, "A");
    assert.equal(result.code, "MALFORMED_STRUCTURE");
  });

  it("identifies when token B fails to decode", () => {
    const result = compareJwts(TOKEN_A, "not-a-jwt");
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.token, "B");
    assert.equal(result.code, "MALFORMED_STRUCTURE");
  });

  it("adds friendly timestamp interpretation for time claims", () => {
    const result = compareJwts(TOKEN_A, TOKEN_B);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    const iat = result.payload.fields.find((field) => field.path === "iat");
    assert.ok(iat?.interpretedValueA?.includes("Local:"));
    assert.ok(iat?.interpretedValueA?.includes("UTC:"));
    assert.equal(iat?.rawValueA, "1516239022");
  });
});

describe("filterChangedFields", () => {
  it("removes unchanged fields", () => {
    const result = compareJwts(TOKEN_A, TOKEN_B);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    const filtered = filterChangedFields(result.payload.fields);
    assert.ok(filtered.every((field) => field.kind !== "unchanged"));
    assert.ok(filtered.length < result.payload.fields.length);
  });
});
