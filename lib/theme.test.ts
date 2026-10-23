import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isTheme, shouldUseDarkTheme } from "./theme";

describe("theme", () => {
  it("validates stored theme values", () => {
    assert.equal(isTheme("light"), true);
    assert.equal(isTheme("dark"), true);
    assert.equal(isTheme("system"), true);
    assert.equal(isTheme("sepia"), false);
    assert.equal(isTheme(null), false);
  });

  it("resolves dark mode from theme and system preference", () => {
    assert.equal(shouldUseDarkTheme("dark", false), true);
    assert.equal(shouldUseDarkTheme("light", true), false);
    assert.equal(shouldUseDarkTheme("system", true), true);
    assert.equal(shouldUseDarkTheme("system", false), false);
  });
});
