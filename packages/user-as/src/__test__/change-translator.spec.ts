import { describe, expect, it } from "vite-plus/test";
import { translateChanges } from "../change-translator";
import type { TCumulativeChanges } from "@aoothjs/user";

describe("translateChanges", () => {
  it("returns null for empty changes", () => {
    expect(translateChanges({})).toBeNull();
  });

  it("translates set operation to nested value", () => {
    const changes: TCumulativeChanges = {
      "account.active": { oldValue: false, value: true, op: "set" },
    };
    expect(translateChanges(changes)).toEqual({
      account: { active: true },
    });
  });

  it("translates deeply nested set operation", () => {
    const changes: TCumulativeChanges = {
      "mfa.email.confirmed": { oldValue: false, value: true, op: "set" },
    };
    expect(translateChanges(changes)).toEqual({
      mfa: { email: { confirmed: true } },
    });
  });

  it("translates unset operation to null", () => {
    const changes: TCumulativeChanges = {
      "account.lockReason": { oldValue: "too many attempts", value: undefined, op: "unset" },
    };
    expect(translateChanges(changes)).toEqual({
      account: { lockReason: null },
    });
  });

  it("translates inc operation to $inc", () => {
    const changes: TCumulativeChanges = {
      "account.failedLoginAttempts": { oldValue: 2, value: 1, op: "inc" },
    };
    expect(translateChanges(changes)).toEqual({
      account: { failedLoginAttempts: { $inc: 1 } },
    });
  });

  it("translates multiple operations in one changeset", () => {
    const changes: TCumulativeChanges = {
      "account.locked": { oldValue: false, value: true, op: "set" },
      "account.lockReason": { oldValue: "", value: "too many attempts", op: "set" },
      "account.failedLoginAttempts": { oldValue: 4, value: 1, op: "inc" },
    };
    expect(translateChanges(changes)).toEqual({
      account: {
        locked: true,
        lockReason: "too many attempts",
        failedLoginAttempts: { $inc: 1 },
      },
    });
  });

  it("translates top-level field", () => {
    const changes: TCumulativeChanges = {
      username: { oldValue: "old", value: "new", op: "set" },
    };
    expect(translateChanges(changes)).toEqual({ username: "new" });
  });

  it("translates set with complex value (array)", () => {
    const changes: TCumulativeChanges = {
      "password.history": {
        oldValue: [],
        value: [{ algorithm: "sha3-224", hash: "abc" }],
        op: "set",
      },
    };
    expect(translateChanges(changes)).toEqual({
      password: { history: [{ algorithm: "sha3-224", hash: "abc" }] },
    });
  });
});
