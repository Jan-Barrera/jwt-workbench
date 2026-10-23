import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  buildCleanUrl,
  sanitizeUrlSearchParams,
} from "./url";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

describe("sanitizeUrlSearchParams", () => {
  it("removes known sensitive parameter names", () => {
    const params = new URLSearchParams(
      "token=abc&jwt=def&theme=dark&access_token=ghi",
    );
    const { sanitized, removed } = sanitizeUrlSearchParams(params);
    assert.deepEqual(removed.sort(), ["access_token", "jwt", "token"]);
    assert.equal(sanitized.get("theme"), "dark");
    assert.equal(sanitized.get("token"), null);
  });

  it("removes parameters whose values look like JWTs", () => {
    const params = new URLSearchParams(`data=${SAMPLE_JWT}&view=decoder`);
    const { sanitized, removed } = sanitizeUrlSearchParams(params);
    assert.deepEqual(removed, ["data"]);
    assert.equal(sanitized.get("view"), "decoder");
  });
});

describe("buildCleanUrl", () => {
  it("returns pathname only when all params are sensitive", () => {
    const params = new URLSearchParams(`jwt=${SAMPLE_JWT}`);
    assert.equal(buildCleanUrl("/", params), "/");
  });

  it("preserves safe query parameters", () => {
    const params = new URLSearchParams("jwt=secret&tab=compare");
    assert.equal(buildCleanUrl("/workbench", params), "/workbench?tab=compare");
  });
});
