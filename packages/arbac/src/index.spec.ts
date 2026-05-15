import { describe, expect, it } from "vite-plus/test";

import * as mod from "./index";

describe("@aoothjs/arbac barrel — ISSUE-21: renamed privilege factories must be absent", () => {
  // Hard-cut contract: the old factory names were replaced by allow* equivalents.
  // Any re-export of the old names would silently expose two ways to do the same
  // thing and break the hard-cut guarantee. These tests catch that regression.
  it("tableReadPrivilege is NOT in the public API", () => {
    expect("tableReadPrivilege" in mod).toBe(false);
  });
  it("tableWritePrivilege is NOT in the public API", () => {
    expect("tableWritePrivilege" in mod).toBe(false);
  });
  it("tableActionsPrivilege is NOT in the public API", () => {
    expect("tableActionsPrivilege" in mod).toBe(false);
  });
  it("tableActionPrivilege is NOT in the public API", () => {
    expect("tableActionPrivilege" in mod).toBe(false);
  });
});

describe("@aoothjs/arbac barrel — ISSUE-23: canAccess and canCrud must be absent", () => {
  // Hard-cut contract: canAccess and canCrud were deleted from @aoothjs/arbac.
  // Callers must use the allow* privilege factories instead. These tests prevent
  // accidental re-introduction of the removed helpers via re-exports or regressions.
  it("canAccess is NOT in the public API", () => {
    expect("canAccess" in mod).toBe(false);
  });
  it("canCrud is NOT in the public API", () => {
    expect("canCrud" in mod).toBe(false);
  });
});

describe("@aoothjs/arbac barrel — new API is present", () => {
  // Positive guard: the replacement names must be present so this spec also
  // acts as a smoke-test that the barrel wires up correctly after the renames.
  it("allowTableRead is exported", () => {
    expect(typeof mod.allowTableRead).toBe("function");
  });
  it("allowTableWrite is exported", () => {
    expect(typeof mod.allowTableWrite).toBe("function");
  });
  it("allowTableAction is exported", () => {
    expect(typeof mod.allowTableAction).toBe("function");
  });
});
