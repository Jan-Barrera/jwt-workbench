import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { formatJson } from "./json-format";

describe("formatJson", () => {
  it("pretty-prints JSON", () => {
    const result = formatJson('{"a":1,"b":[2]}', "pretty");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.match(result.output, /\n/);
    assert.match(result.output, /"a": 1/);
  });

  it("minifies JSON", () => {
    const result = formatJson('{\n  "a": 1\n}\n', "minify");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.output, '{"a":1}');
  });

  it("reports invalid JSON", () => {
    const result = formatJson("{ broken", "pretty");
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.match(result.message, /Invalid JSON/i);
  });
});
