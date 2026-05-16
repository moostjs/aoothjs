import { describe, it, expect } from "vite-plus/test";

import * as rootBarrel from "./index";

/**
 * The `@atscript/db` adapter lives at the `@aoothjs/user/atscript-db` subpath
 * so consumers don't pay the `@atscript/db` peer cost when they only need the
 * core primitives. The class previously named `UsersStoreAs` lived in the
 * deleted `@aoothjs/user-as` package; nothing referencing either name should
 * leak into the root barrel.
 *
 * These negatives are why we have this spec — failure here means a future
 * "convenience re-export" silently broke the subpath contract that keeps the
 * core import optional-peer-free.
 */
describe("@aoothjs/user root barrel", () => {
  it("does not export UsersStoreAs (deleted package)", () => {
    expect("UsersStoreAs" in rootBarrel).toBe(false);
  });

  it("does not export UsersStoreAtscriptDb (subpath-only)", () => {
    expect("UsersStoreAtscriptDb" in rootBarrel).toBe(false);
  });

  it("does not export AuthUserTable (subpath-only)", () => {
    expect("AuthUserTable" in rootBarrel).toBe(false);
  });

  it("exposes the abstract UserStore so consumers can implement their own", () => {
    expect("UserStore" in rootBarrel).toBe(true);
  });
});

describe("@aoothjs/user/atscript-db subpath", () => {
  it("exports UsersStoreAtscriptDb (the only access point)", async () => {
    const subpath = await import("./atscript-db/index");
    expect(typeof subpath.UsersStoreAtscriptDb).toBe("function");
  });
});
