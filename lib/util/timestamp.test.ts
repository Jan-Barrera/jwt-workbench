import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { convertUnixTimestamp } from "./timestamp";

describe("convertUnixTimestamp", () => {
  it("converts seconds", () => {
    const result = convertUnixTimestamp("1516239022");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.raw, "1516239022");
    assert.equal(result.unit, "seconds");
    assert.equal(result.epochSeconds, 1516239022);
    assert.match(result.utc, /2018/);
    assert.ok(result.local.length > 0);
  });

  it("treats long values as milliseconds", () => {
    const result = convertUnixTimestamp("1516239022000");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.unit, "milliseconds");
    assert.equal(result.epochSeconds, 1516239022);
  });

  it("rejects non-numeric input", () => {
    const result = convertUnixTimestamp("not-a-timestamp");
    assert.equal(result.ok, false);
  });

  it("rejects empty input", () => {
    const result = convertUnixTimestamp("  ");
    assert.equal(result.ok, false);
  });
});
