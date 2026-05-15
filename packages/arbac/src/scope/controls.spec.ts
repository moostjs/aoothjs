import { describe, expect, it } from "vite-plus/test";

import { unionControlsPolicy } from "./controls";
import type { ControlGate } from "./types";

describe("unionControlsPolicy", () => {
  it("returns {} for empty input", () => {
    expect(unionControlsPolicy([])).toStrictEqual({});
  });

  it("returns {} when any scope has no controls map (silent on everything)", () => {
    expect(unionControlsPolicy([{}, { controls: { $with: false } }])).toStrictEqual({});
  });

  // Single-scope cases -------------------------------------------------------

  it("single scope: silence on a key produces no entry", () => {
    expect(unionControlsPolicy([{ controls: {} }])).toStrictEqual({});
  });

  it("single scope: explicit `true` gate is dropped (absent === allowed)", () => {
    expect(unionControlsPolicy([{ controls: { $with: true } }])).toStrictEqual({});
  });

  it("single scope: `false` gate denies the key", () => {
    expect(unionControlsPolicy([{ controls: { $with: false } }])).toStrictEqual({
      $with: false,
    });
  });

  it("single scope: whitelist gate is preserved (sorted)", () => {
    expect(unionControlsPolicy([{ controls: { $with: ["tasks", "comments"] } }])).toStrictEqual({
      $with: ["comments", "tasks"],
    });
  });

  // Two-scope cases ----------------------------------------------------------

  it("two scopes: silence + false → key not in result (silence wins → allowed)", () => {
    expect(unionControlsPolicy([{ controls: {} }, { controls: { $with: false } }])).toStrictEqual(
      {},
    );
  });

  it("two scopes: silence + whitelist → silence wins → key not in result", () => {
    expect(
      unionControlsPolicy([{ controls: {} }, { controls: { $with: ["comments"] } }]),
    ).toStrictEqual({});
  });

  it("two scopes: false + false → false", () => {
    expect(
      unionControlsPolicy([{ controls: { $with: false } }, { controls: { $with: false } }]),
    ).toStrictEqual({ $with: false });
  });

  it("two scopes: false + whitelist → whitelist (false roles don't contribute positively)", () => {
    expect(
      unionControlsPolicy([{ controls: { $with: false } }, { controls: { $with: ["comments"] } }]),
    ).toStrictEqual({ $with: ["comments"] });
  });

  it("two scopes: whitelist + whitelist → de-duplicated, sorted union", () => {
    expect(
      unionControlsPolicy([
        { controls: { $with: ["comments", "owner"] } },
        { controls: { $with: ["tasks", "comments"] } },
      ]),
    ).toStrictEqual({ $with: ["comments", "owner", "tasks"] });
  });

  it("two scopes: explicit true beats false on the same key", () => {
    expect(
      unionControlsPolicy([{ controls: { $with: false } }, { controls: { $with: true } }]),
    ).toStrictEqual({});
  });

  // Three-scope edge cases ---------------------------------------------------

  it("three scopes: false + whitelist + false → whitelist", () => {
    expect(
      unionControlsPolicy([
        { controls: { $with: false } },
        { controls: { $with: ["comments"] } },
        { controls: { $with: false } },
      ]),
    ).toStrictEqual({ $with: ["comments"] });
  });

  it("three scopes: false + whitelist + true → fully allowed (key dropped)", () => {
    expect(
      unionControlsPolicy([
        { controls: { $with: false } },
        { controls: { $with: ["comments"] } },
        { controls: { $with: true } },
      ]),
    ).toStrictEqual({});
  });

  // Mixed control keys -------------------------------------------------------

  it("mixed control keys: per-key resolution is independent (silent-on-key === allow)", () => {
    // A is silent on $having → $having dropped (allowed).
    // B is silent on $groupBy → $groupBy dropped (allowed).
    // $with: false + ['comments'] → whitelist wins.
    expect(
      unionControlsPolicy([
        { controls: { $with: false, $groupBy: ["status"] } },
        { controls: { $with: ["comments"], $having: false } },
      ]),
    ).toStrictEqual({ $with: ["comments"] });
  });

  it("mixed: a scope silent on $with + a scope whitelisting $with → $with allowed", () => {
    // First scope silent on $with → allowed; silent on $groupBy → key not in result.
    // Wait — first scope has $groupBy:false; second scope silent on $groupBy → allowed.
    // First scope silent on $with; second scope whitelists → allowed.
    // Net: {} (both keys allowed).
    expect(
      unionControlsPolicy([
        { controls: { $groupBy: false } },
        { controls: { $with: ["comments"] } },
      ]),
    ).toStrictEqual({});
  });

  it("mixed: both scopes deny $groupBy, A whitelists $with, B silent on $with → $groupBy denied, $with allowed", () => {
    expect(
      unionControlsPolicy([
        { controls: { $groupBy: false, $with: ["comments"] } },
        { controls: { $groupBy: false } },
      ]),
    ).toStrictEqual({ $groupBy: false });
  });

  // Whitelist support gating -------------------------------------------------

  it("throws when a non-whitelistable control receives a string[] gate", () => {
    expect(() =>
      unionControlsPolicy([
        { controls: { $having: ["count"] as readonly string[] as ControlGate } },
      ]),
    ).toThrow(/\$having.*boolean/);
  });

  it("does NOT throw for $having with a boolean gate", () => {
    expect(unionControlsPolicy([{ controls: { $having: false } }])).toStrictEqual({
      $having: false,
    });
    expect(unionControlsPolicy([{ controls: { $having: true } }])).toStrictEqual({});
  });
});
