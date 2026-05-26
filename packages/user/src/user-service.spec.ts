import { describe, expect, it, beforeEach } from "vite-plus/test";
import { UserAuthError } from "./errors";
import { generateTotpCode, generateTotpSecret } from "./mfa/totp";
import { ppHasMinLength, ppHasUpperCase } from "./password/policies";
import { UserService } from "./user-service";
import { UserStoreMemory } from "./store/memory";

// Low-cost scrypt for fast tests
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };

async function createActiveUser(svc: UserService, username: string, password?: string) {
  const user = await svc.createUser(username, password);
  await svc.activateAccount(username);
  return user;
}

describe("UserService", () => {
  let store: UserStoreMemory;
  let svc: UserService;
  let now: number;

  beforeEach(() => {
    now = 1000000;
    store = new UserStoreMemory();
    svc = new UserService(store, {
      password: { ...FAST_SCRYPT },
      clock: () => now,
    });
  });

  describe("createUser", () => {
    it("should create a user with a system-generated password", async () => {
      const user = await svc.createUser("alice");
      expect(user.username).toBe("alice");
      expect(user.password.hash).toMatch(/^\$scrypt\$/);
      expect(user.password.isInitial).toBe(true);
      expect(user.account.active).toBe(false);
      expect(user.mfa.methods).toEqual([]);
    });

    it("should create a user with a provided password", async () => {
      const user = await svc.createUser("alice", "MyPassword1!");
      expect(user.password.isInitial).toBe(false);
      expect(await svc.verifyPassword("alice", "MyPassword1!")).toBe(true);
    });

    it("should throw ALREADY_EXISTS for duplicate", async () => {
      await svc.createUser("alice");
      try {
        await svc.createUser("alice");
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(UserAuthError);
        expect((e as UserAuthError).type).toBe("ALREADY_EXISTS");
      }
    });

    it("should merge extras into the created user", async () => {
      interface CustomUser {
        tenantId?: string;
        roles?: string[];
      }
      const customStore = new UserStoreMemory<CustomUser>();
      const customSvc = new UserService<CustomUser>(customStore, {
        password: { ...FAST_SCRYPT },
        clock: () => now,
      });
      const user = await customSvc.createUser("alice", "pass123", {
        tenantId: "acme",
        roles: ["admin"],
      });
      expect(user.tenantId).toBe("acme");
      expect(user.roles).toEqual(["admin"]);
      // Base shape is preserved (extras merge AFTER base, but don't clobber
      // unrelated fields).
      expect(user.username).toBe("alice");
      expect(user.account.active).toBe(false);
    });

    it("extras can override base UserCredentials fields", async () => {
      // `id` is the canonical case — consumers' DB schemas often replace the
      // empty-string default with a UUID/ID generator.
      const user = await svc.createUser("alice", "pass123", {
        // biome-ignore lint/suspicious/noExplicitAny: cross-extending base shape in test
        id: "user-123",
      } as any);
      expect(user.id).toBe("user-123");
    });

    // Regression for ISSUE-27 — a hard-coded `id: ""` on the base record
    // shadowed atscript-db's `@db.default.uuid` so every invite-created user
    // collided on PK, causing the second `create` to fail with UNIQUE.
    // The contract being verified: `createUser` MUST NOT put any `id`
    // property on the record handed to the store unless the caller provided
    // one via `extras`. That way the store's defaults (UUID, sequence, ...)
    // can fire on each insert.
    it("does NOT include `id` on the record passed to store.create when no id is supplied", async () => {
      let received: Record<string, unknown> | undefined;
      const recordingStore = new UserStoreMemory();
      const originalCreate = recordingStore.create.bind(recordingStore);
      recordingStore.create = async (data) => {
        received = data as unknown as Record<string, unknown>;
        return originalCreate(data);
      };
      const recSvc = new UserService(recordingStore, {
        password: { ...FAST_SCRYPT },
        clock: () => now,
      });
      await recSvc.createUser("alice", "pass123");
      expect(received).toBeDefined();
      // Use `in` so we catch `id: ""` / `id: undefined` — the original bug
      // was `id: ""` overwriting the DB default.
      expect("id" in (received as object)).toBe(false);
    });

    it("DOES include caller-supplied `id` on the record passed to store.create", async () => {
      let received: Record<string, unknown> | undefined;
      const recordingStore = new UserStoreMemory<{ id?: string }>();
      const originalCreate = recordingStore.create.bind(recordingStore);
      recordingStore.create = async (data) => {
        received = data as unknown as Record<string, unknown>;
        return originalCreate(data);
      };
      const recSvc = new UserService<{ id?: string }>(recordingStore, {
        password: { ...FAST_SCRYPT },
        clock: () => now,
      });
      await recSvc.createUser("alice", "pass123", { id: "explicit-id" });
      expect(received).toBeDefined();
      expect("id" in (received as object)).toBe(true);
      expect(received!.id).toBe("explicit-id");
    });
  });

  describe("getUser", () => {
    it("should return user data", async () => {
      await svc.createUser("alice");
      const user = await svc.getUser("alice");
      expect(user.username).toBe("alice");
    });

    it("should throw NOT_FOUND for unknown user", async () => {
      try {
        await svc.getUser("unknown");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });
  });

  describe("login", () => {
    it("should throw INACTIVE for inactive account", async () => {
      await svc.createUser("alice", "pass123");
      try {
        await svc.login("alice", "pass123");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("INACTIVE");
      }
    });

    it("should succeed with correct password", async () => {
      await createActiveUser(svc, "alice", "pass123");
      const result = await svc.login("alice", "pass123");
      expect(result.user.username).toBe("alice");
      expect(result.user.account.lastLogin).toBe(now);
      expect(result.mfaRequired).toBe(false);
    });

    it("should throw INVALID_CREDENTIALS for wrong password", async () => {
      await createActiveUser(svc, "alice", "pass123");
      try {
        await svc.login("alice", "wrong");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("INVALID_CREDENTIALS");
      }
    });

    it("should throw NOT_FOUND for unknown user", async () => {
      try {
        await svc.login("unknown", "pass");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });

    it("should increment failedLoginAttempts on failure", async () => {
      await createActiveUser(svc, "alice", "pass123");
      try {
        await svc.login("alice", "wrong");
      } catch {}
      try {
        await svc.login("alice", "wrong");
      } catch {}
      const user = await svc.getUser("alice");
      expect(user.account.failedLoginAttempts).toBe(2);
    });

    it("should reset failedLoginAttempts on success", async () => {
      await createActiveUser(svc, "alice", "pass123");
      try {
        await svc.login("alice", "wrong");
      } catch {}
      await svc.login("alice", "pass123");
      const user = await svc.getUser("alice");
      expect(user.account.failedLoginAttempts).toBe(0);
    });

    it("should indicate mfaRequired when MFA methods are confirmed", async () => {
      await createActiveUser(svc, "alice", "pass123");
      await svc.addMfaMethod("alice", {
        name: "totp",
        confirmed: true,
        value: "ABCDEF",
      });
      const result = await svc.login("alice", "pass123");
      expect(result.mfaRequired).toBe(true);
    });
  });

  describe("lockout", () => {
    let lockSvc: UserService;

    beforeEach(() => {
      lockSvc = new UserService(store, {
        password: { ...FAST_SCRYPT },
        lockout: { threshold: 3, duration: 60000 },
        clock: () => now,
      });
    });

    it("should lock account after threshold failures", async () => {
      await createActiveUser(lockSvc, "alice", "pass123");
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const user = await lockSvc.getUser("alice");
      expect(user.account.locked).toBe(true);
      expect(user.account.lockReason).toBe("Too many login attempts");
    });

    it("should throw LOCKED on login when account is locked", async () => {
      await createActiveUser(lockSvc, "alice", "pass123");
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      try {
        await lockSvc.login("alice", "pass123");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("LOCKED");
        expect((e as UserAuthError).details?.lockEnds).toBe(now + 60000);
      }
    });

    it("should auto-unlock after lock duration expires", async () => {
      await createActiveUser(lockSvc, "alice", "pass123");
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      // Advance time past lock duration
      now += 61000;
      const result = await lockSvc.login("alice", "pass123");
      expect(result.user.username).toBe("alice");
    });

    it("should support permanent lock (duration=0)", async () => {
      const permSvc = new UserService(store, {
        password: { ...FAST_SCRYPT },
        lockout: { threshold: 3, duration: 0 },
        clock: () => now,
      });
      await createActiveUser(permSvc, "alice", "pass123");
      for (let i = 0; i < 3; i++) {
        try {
          await permSvc.login("alice", "wrong");
        } catch {}
      }
      // Even after a long time, permanent lock persists
      now += 999999999;
      try {
        await permSvc.login("alice", "pass123");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("LOCKED");
      }
    });
  });

  describe("lockout — case sensitivity invariant", () => {
    // WHY: `findByUsername` and the lockout key are both case-sensitive today
    // (literal `username` string). These tests pin that invariant so a future
    // "let's make username lookup case-insensitive" change can't silently
    // break the lockout side: if lookup goes case-insensitive while the
    // lockout key stays literal, an attacker could dodge throttle via case
    // variants on the SAME underlying account. Conversely, NOT_FOUND probes
    // on a non-existent variant must not leak into a real account's budget.
    let lockSvc: UserService;

    beforeEach(() => {
      lockSvc = new UserService(store, {
        password: { ...FAST_SCRYPT },
        lockout: { threshold: 3, duration: 60000 },
        clock: () => now,
      });
    });

    it("alice and Alice are independent accounts — locking alice does not affect Alice", async () => {
      // Two accounts that differ only in case must have INDEPENDENT lockout
      // budgets. Two accounts = two budgets; collapsing them would let one
      // account's failures DoS the other.
      await createActiveUser(lockSvc, "alice", "pass123");
      await createActiveUser(lockSvc, "Alice", "pass123");

      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const lower = await lockSvc.getUser("alice");
      expect(lower.account.locked).toBe(true);

      // `Alice` must still authenticate cleanly with her own credentials.
      const result = await lockSvc.login("Alice", "pass123");
      expect(result.user.username).toBe("Alice");
      const upper = await lockSvc.getUser("Alice");
      expect(upper.account.locked).toBe(false);
      expect(upper.account.failedLoginAttempts).toBe(0);
    });

    it("case-variant probing of a non-existent account does NOT inflate the real account's lockout budget", async () => {
      // Seed only `alice` (lowercase). `Alice` does not exist.
      await createActiveUser(lockSvc, "alice", "pass123");

      // Probe the non-existent variant `Alice` 3 times — each must surface as
      // NOT_FOUND and must NOT be charged to `alice`'s budget.
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("Alice", "wrong");
          expect.unreachable();
        } catch (e) {
          expect((e as UserAuthError).type).toBe("NOT_FOUND");
        }
      }

      // `alice`'s failure counter must still be zero — variant probes did not
      // bleed across.
      const before = await lockSvc.getUser("alice");
      expect(before.account.failedLoginAttempts).toBe(0);
      expect(before.account.locked).toBe(false);

      // Now drive `alice` to (threshold - 1) bad attempts: she must STILL be
      // unlocked — proving the variant probes didn't pre-charge her counter.
      for (let i = 0; i < 2; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const mid = await lockSvc.getUser("alice");
      expect(mid.account.locked).toBe(false);
      expect(mid.account.failedLoginAttempts).toBe(2);

      // The Nth (threshold) bad alice-attempt must trip the lock — exactly N,
      // not 2N. If the variant probes had counted, this would have fired earlier.
      try {
        await lockSvc.login("alice", "wrong");
      } catch {}
      const locked = await lockSvc.getUser("alice");
      expect(locked.account.locked).toBe(true);
    });
  });

  describe("changePassword", () => {
    it("should change password with correct current password", async () => {
      await svc.createUser("alice", "oldpass");
      await svc.changePassword("alice", "oldpass", "newpass");
      expect(await svc.verifyPassword("alice", "newpass")).toBe(true);
      expect(await svc.verifyPassword("alice", "oldpass")).toBe(false);
    });

    it("should throw INVALID_CREDENTIALS for wrong current password", async () => {
      await svc.createUser("alice", "oldpass");
      try {
        await svc.changePassword("alice", "wrong", "newpass");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("INVALID_CREDENTIALS");
      }
    });

    it("should throw PASSWORDS_MISMATCH when repeat doesn't match", async () => {
      await svc.createUser("alice", "oldpass");
      try {
        await svc.changePassword("alice", "oldpass", "newpass", "different");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("PASSWORDS_MISMATCH");
      }
    });

    it("should throw PASSWORD_IN_HISTORY for current password reuse", async () => {
      await svc.createUser("alice", "mypass");
      try {
        await svc.changePassword("alice", "mypass", "mypass");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("PASSWORD_IN_HISTORY");
      }
    });

    it("should enforce password history", async () => {
      const historySvc = new UserService(store, {
        password: { ...FAST_SCRYPT, historyLength: 3 },
        clock: () => now,
      });
      await historySvc.createUser("alice", "pass1");
      await historySvc.changePassword("alice", "pass1", "pass2");
      await historySvc.changePassword("alice", "pass2", "pass3");

      // pass1 should be in history
      try {
        await historySvc.changePassword("alice", "pass3", "pass1");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("PASSWORD_IN_HISTORY");
      }
    });

    it("should enforce password policies", async () => {
      const policySvc = new UserService(store, {
        password: { ...FAST_SCRYPT, policies: [ppHasMinLength(8), ppHasUpperCase(1)] },
        clock: () => now,
      });
      await policySvc.createUser("alice", "OldPass1!");
      try {
        await policySvc.changePassword("alice", "OldPass1!", "short");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("POLICY_VIOLATION");
      }
    });
  });

  describe("isPasswordExpired", () => {
    // WHY: missing config must NEVER force-expire. Consumers who never opt
    // in to expiry would otherwise get force-locked-out after long
    // deployments — a silent footgun where simply running a long-lived
    // service would start failing logins. Pins "no config => no expiry".
    it("returns false when maxAgeMs is unset", async () => {
      const user = await svc.createUser("alice");
      // Advance the clock 100 years past the user's lastChanged.
      now += 100 * 365 * 24 * 60 * 60 * 1000;
      expect(svc.isPasswordExpired(user)).toBe(false);
    });

    // WHY: an unrecorded `lastChanged` (0 / falsy) must not trigger expiry.
    // Otherwise legacy or imported users whose timestamp was never captured
    // would force-loop the forced-change flow on every login — they'd
    // change their password, the store-side import didn't stamp
    // `lastChanged`, and the next login would expire it again.
    it("returns false when lastChanged is 0", () => {
      const svcExpiry = new UserService(store, {
        password: { ...FAST_SCRYPT, maxAgeMs: 1000 },
        clock: () => now,
      });
      // Construct a literal directly — avoid `createUser` which stamps the
      // current clock onto `lastChanged`.
      const user = {
        id: "x",
        username: "alice",
        password: { hash: "", history: [], lastChanged: 0, isInitial: false },
        account: {
          active: true,
          locked: false,
          lockReason: "",
          lockEnds: 0,
          failedLoginAttempts: 0,
          lastLogin: 0,
        },
        mfa: { methods: [], defaultMethod: "", autoSend: false },
      };
      // Far past any plausible window — proves it's the `lastChanged` guard
      // and not a window check that gives `false`.
      expect(svcExpiry.isPasswordExpired(user, 1_000_000_000)).toBe(false);
    });

    // WHY: pins the inequality direction. A regression flipping `>` to `<`
    // or to `>=` would either expire prematurely (every fresh login fails)
    // or never expire (4s elapsed under a 10s window is the boundary that
    // catches both). Uses the default `now` arg to also cover the
    // implicit `this.config.clock()` binding.
    it("returns false when within window", async () => {
      const svcExpiry = new UserService(store, {
        password: { ...FAST_SCRYPT, maxAgeMs: 10_000 },
        clock: () => now,
      });
      now = 1000;
      const user = await svcExpiry.createUser("alice");
      now = 5000; // 4s elapsed, well under 10s window
      expect(svcExpiry.isPasswordExpired(user)).toBe(false);
    });

    // WHY: positive-case proof the predicate fires at all. Without this
    // the three negative tests above could all pass against a hardcoded
    // `return false`. Passes `now` explicitly to cover the override path
    // (the symmetric case to test 3's default-binding coverage).
    it("returns true when beyond window", async () => {
      const svcExpiry = new UserService(store, {
        password: { ...FAST_SCRYPT, maxAgeMs: 10_000 },
        clock: () => now,
      });
      now = 1000;
      const user = await svcExpiry.createUser("alice");
      // 11s elapsed, past 10s window — explicit `now` arg.
      expect(svcExpiry.isPasswordExpired(user, 12_000)).toBe(true);
    });
  });

  describe("setPassword", () => {
    it("should set password without current password verification", async () => {
      await svc.createUser("alice", "oldpass");
      await svc.setPassword("alice", "newpass");
      expect(await svc.verifyPassword("alice", "newpass")).toBe(true);
    });
  });

  describe("account management", () => {
    it("should activate account", async () => {
      await svc.createUser("alice");
      await svc.activateAccount("alice");
      const user = await svc.getUser("alice");
      expect(user.account.active).toBe(true);
    });

    it("should deactivate account", async () => {
      await svc.createUser("alice");
      await svc.activateAccount("alice");
      await svc.deactivateAccount("alice");
      const user = await svc.getUser("alice");
      expect(user.account.active).toBe(false);
    });

    it("should lock account with reason and duration", async () => {
      await svc.createUser("alice");
      await svc.lockAccount("alice", "Suspicious activity", 60000);
      const user = await svc.getUser("alice");
      expect(user.account.locked).toBe(true);
      expect(user.account.lockReason).toBe("Suspicious activity");
      expect(user.account.lockEnds).toBe(now + 60000);
    });

    it("should lock permanently when no duration", async () => {
      await svc.createUser("alice");
      await svc.lockAccount("alice", "Banned");
      const user = await svc.getUser("alice");
      expect(user.account.locked).toBe(true);
      expect(user.account.lockEnds).toBe(0);
    });

    it("should unlock account and reset failed attempts", async () => {
      await svc.createUser("alice");
      await svc.lockAccount("alice", "test");
      await svc.unlockAccount("alice");
      const user = await svc.getUser("alice");
      expect(user.account.locked).toBe(false);
      expect(user.account.lockReason).toBe("");
      expect(user.account.failedLoginAttempts).toBe(0);
    });

    it("should throw NOT_FOUND for unknown user", async () => {
      try {
        await svc.activateAccount("unknown");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });
  });

  describe("getLockStatus", () => {
    it("should return unlocked status", () => {
      const status = svc.getLockStatus({
        active: true,
        locked: false,
        lockReason: "",
        lockEnds: 0,
        failedLoginAttempts: 0,
        lastLogin: 0,
      });
      expect(status.locked).toBe(false);
      expect(status.expired).toBe(false);
    });

    it("should detect expired timed lock", () => {
      const status = svc.getLockStatus({
        active: true,
        locked: true,
        lockReason: "test",
        lockEnds: now - 1000,
        failedLoginAttempts: 0,
        lastLogin: 0,
      });
      expect(status.locked).toBe(true);
      expect(status.expired).toBe(true);
    });

    it("should detect active timed lock", () => {
      const status = svc.getLockStatus({
        active: true,
        locked: true,
        lockReason: "test",
        lockEnds: now + 60000,
        failedLoginAttempts: 0,
        lastLogin: 0,
      });
      expect(status.locked).toBe(true);
      expect(status.expired).toBe(false);
    });

    it("should detect permanent lock (lockEnds=0)", () => {
      const status = svc.getLockStatus({
        active: true,
        locked: true,
        lockReason: "banned",
        lockEnds: 0,
        failedLoginAttempts: 0,
        lastLogin: 0,
      });
      expect(status.locked).toBe(true);
      expect(status.expired).toBe(false);
    });
  });

  describe("checkPolicies", () => {
    it("should evaluate all policies and return results", async () => {
      const policySvc = new UserService(store, {
        password: { ...FAST_SCRYPT, policies: [ppHasMinLength(8), ppHasUpperCase(1)] },
        clock: () => now,
      });
      const result = await policySvc.checkPolicies("short");
      expect(result.passed).toBe(false);
      expect(result.policies).toHaveLength(2);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("should pass when all policies are met", async () => {
      const policySvc = new UserService(store, {
        password: { ...FAST_SCRYPT, policies: [ppHasMinLength(4)] },
        clock: () => now,
      });
      const result = await policySvc.checkPolicies("LongEnough");
      expect(result.passed).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe("getTransferablePolicies", () => {
    it("should return only string-rule policies", () => {
      const mixed = new UserService(store, {
        password: {
          ...FAST_SCRYPT,
          policies: [ppHasMinLength(8), { rule: () => true, description: "Custom" }],
        },
        clock: () => now,
      });
      const transferable = mixed.getTransferablePolicies();
      expect(transferable).toHaveLength(1);
      expect(transferable[0].rule).toContain("v.length");
    });
  });

  describe("MFA management", () => {
    beforeEach(async () => {
      await svc.createUser("alice", "pass123");
    });

    it("should add an MFA method", async () => {
      await svc.addMfaMethod("alice", { name: "email", confirmed: false, value: "alice@test.com" });
      const user = await svc.getUser("alice");
      const method = user.mfa.methods.find((m) => m.name === "email");
      expect(method).toBeDefined();
      expect(method!.confirmed).toBe(false);
      expect(method!.value).toBe("alice@test.com");
    });

    it("should replace existing method with same name", async () => {
      await svc.addMfaMethod("alice", { name: "email", confirmed: false, value: "old@test.com" });
      await svc.addMfaMethod("alice", { name: "email", confirmed: false, value: "new@test.com" });
      const user = await svc.getUser("alice");
      expect(user.mfa.methods.filter((m) => m.name === "email")).toHaveLength(1);
      expect(user.mfa.methods.find((m) => m.name === "email")!.value).toBe("new@test.com");
    });

    it("should confirm an MFA method", async () => {
      await svc.addMfaMethod("alice", { name: "email", confirmed: false, value: "alice@test.com" });
      await svc.confirmMfaMethod("alice", "email");
      const user = await svc.getUser("alice");
      expect(user.mfa.methods.find((m) => m.name === "email")!.confirmed).toBe(true);
    });

    it("should throw MFA_NOT_CONFIGURED for unknown method", async () => {
      try {
        await svc.confirmMfaMethod("alice", "nonexistent");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_NOT_CONFIGURED");
      }
    });

    it("should remove an MFA method", async () => {
      await svc.addMfaMethod("alice", { name: "totp", confirmed: true, value: "ABC" });
      await svc.removeMfaMethod("alice", "totp");
      const user = await svc.getUser("alice");
      expect(user.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();
    });

    it("should clear defaultMethod when removing the default method", async () => {
      await svc.addMfaMethod("alice", { name: "totp", confirmed: true, value: "ABC" });
      await svc.setDefaultMfaMethod("alice", "totp");
      await svc.removeMfaMethod("alice", "totp");
      const user = await svc.getUser("alice");
      expect(user.mfa.defaultMethod).toBe("");
    });

    it("should set default MFA method", async () => {
      await svc.addMfaMethod("alice", { name: "email", confirmed: true, value: "a@b.c" });
      await svc.setDefaultMfaMethod("alice", "email");
      const user = await svc.getUser("alice");
      expect(user.mfa.defaultMethod).toBe("email");
      expect(user.mfa.autoSend).toBe(false);
    });

    it("should throw MFA_NOT_CONFIGURED for setting non-existent default", async () => {
      try {
        await svc.setDefaultMfaMethod("alice", "nonexistent");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_NOT_CONFIGURED");
      }
    });

    it("should get available (confirmed) MFA methods", async () => {
      await svc.addMfaMethod("alice", { name: "email", confirmed: true, value: "alice@test.com" });
      await svc.addMfaMethod("alice", { name: "totp", confirmed: false, value: "ABC" });
      const user = await svc.getUser("alice");
      const methods = svc.getAvailableMfaMethods(user.mfa);
      expect(methods).toHaveLength(1);
      expect(methods[0].name).toBe("email");
      expect(methods[0].masked).toContain("***");
    });

    it("should set MFA autoSend", async () => {
      await svc.setMfaAutoSend("alice", true);
      const user = await svc.getUser("alice");
      expect(user.mfa.autoSend).toBe(true);
    });

    it("REGRESSION — concurrent addMfaMethod must not lose a method", async () => {
      // Two devices enrolling different MFA factors at the same time must
      // both land — the read-modify-write of mfa.methods[] used to drop one.
      await Promise.all([
        svc.addMfaMethod("alice", { name: "totp", confirmed: false, value: "SECRET" }),
        svc.addMfaMethod("alice", { name: "email", confirmed: false, value: "alice@test.com" }),
      ]);
      const user = await svc.getUser("alice");
      expect(user.mfa.methods.map((m) => m.name).toSorted((a, b) => a.localeCompare(b))).toEqual([
        "email",
        "totp",
      ]);
    });

    it("REGRESSION — concurrent confirmMfaMethod must not race with addMfaMethod", async () => {
      // User adds totp via one tab while confirming a pre-existing email
      // factor in another. Both writes must compose — confirming email
      // shouldn't wipe the newly-added totp from the methods array.
      await svc.addMfaMethod("alice", { name: "email", confirmed: false, value: "alice@test.com" });
      await Promise.all([
        svc.addMfaMethod("alice", { name: "totp", confirmed: false, value: "SECRET" }),
        svc.confirmMfaMethod("alice", "email"),
      ]);
      const user = await svc.getUser("alice");
      const byName = Object.fromEntries(user.mfa.methods.map((m) => [m.name, m.confirmed]));
      expect(byName).toEqual({ email: true, totp: false });
    });
  });

  describe("getPasswordHasher", () => {
    it("should return the hasher instance", () => {
      expect(svc.getPasswordHasher()).toBeDefined();
    });
  });

  describe("getConfig", () => {
    it("should return resolved configuration", () => {
      const config = svc.getConfig();
      expect(config.password.scryptN).toBe(1024);
      expect(config.lockout.threshold).toBe(0);
      expect(typeof config.clock).toBe("function");
    });
  });

  describe("setPassword", () => {
    it("should mark isInitial as false and update lastChanged", async () => {
      await svc.createUser("alice");
      const before = await svc.getUser("alice");
      expect(before.password.isInitial).toBe(true);

      now += 1000;
      await svc.setPassword("alice", "newpass123");
      const after = await svc.getUser("alice");
      expect(after.password.isInitial).toBe(false);
      expect(after.password.lastChanged).toBe(now);
    });
  });

  describe("verifyPassword edge cases", () => {
    it("should throw NOT_FOUND for unknown user", async () => {
      try {
        await svc.verifyPassword("unknown", "pass");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });
  });

  describe("login with unconfirmed MFA only", () => {
    it("should return mfaRequired false when all MFA methods are unconfirmed", async () => {
      await createActiveUser(svc, "alice", "pass123");
      await svc.addMfaMethod("alice", { name: "totp", confirmed: false, value: "SECRET" });
      const result = await svc.login("alice", "pass123");
      expect(result.mfaRequired).toBe(false);
    });
  });

  describe("setMfaAutoSend edge cases", () => {
    it("should throw NOT_FOUND for unknown user", async () => {
      try {
        await svc.setMfaAutoSend("unknown", true);
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });
  });

  describe("backup codes", () => {
    beforeEach(async () => {
      await svc.createUser("alice", "pass123");
    });

    it("should generate plaintext codes and persist their hashes", async () => {
      const codes = await svc.generateBackupCodes("alice", 5);
      expect(codes).toHaveLength(5);
      // Plaintext format check
      for (const c of codes) {
        expect(c).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{2}$/);
      }
      const user = await svc.getUser("alice");
      expect(user.backupCodes).toBeDefined();
      expect(user.backupCodes).toHaveLength(5);
      // Hashes should be hex SHA-256 — never the plaintext.
      for (const h of user.backupCodes!) {
        expect(h).toMatch(/^[0-9a-f]{64}$/);
      }
      for (const c of codes) {
        expect(user.backupCodes).not.toContain(c);
      }
    });

    it("should default to 10 codes", async () => {
      const codes = await svc.generateBackupCodes("alice");
      expect(codes).toHaveLength(10);
    });

    it("should replace previous codes when called again", async () => {
      const first = await svc.generateBackupCodes("alice", 4);
      const second = await svc.generateBackupCodes("alice", 6);
      expect(first).not.toEqual(second);
      const user = await svc.getUser("alice");
      expect(user.backupCodes).toHaveLength(6);
      // None of the first batch's codes should still verify.
      for (const c of first) {
        expect(await svc.consumeBackupCode("alice", c)).toBe(false);
      }
    });

    it("should throw NOT_FOUND when generating for an unknown user", async () => {
      try {
        await svc.generateBackupCodes("unknown");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });

    it("should consume a matching backup code and remove its hash", async () => {
      const codes = await svc.generateBackupCodes("alice", 4);
      const before = await svc.getUser("alice");
      expect(before.backupCodes).toHaveLength(4);

      const ok = await svc.consumeBackupCode("alice", codes[1]);
      expect(ok).toBe(true);

      const after = await svc.getUser("alice");
      expect(after.backupCodes).toHaveLength(3);
    });

    it("should return false for a non-matching code without modifying storage", async () => {
      await svc.generateBackupCodes("alice", 3);
      const before = await svc.getUser("alice");
      const ok = await svc.consumeBackupCode("alice", "ZZZZ-ZZZZ-ZZ");
      expect(ok).toBe(false);
      const after = await svc.getUser("alice");
      expect(after.backupCodes).toEqual(before.backupCodes);
    });

    it("should not allow re-using an already-consumed code", async () => {
      const codes = await svc.generateBackupCodes("alice", 3);
      expect(await svc.consumeBackupCode("alice", codes[0])).toBe(true);
      expect(await svc.consumeBackupCode("alice", codes[0])).toBe(false);
    });

    it("REGRESSION — concurrent consume of the same code must succeed at most once", async () => {
      const codes = await svc.generateBackupCodes("alice", 3);
      const [a, b] = await Promise.all([
        svc.consumeBackupCode("alice", codes[0]),
        svc.consumeBackupCode("alice", codes[0]),
      ]);
      expect([a, b].filter(Boolean)).toHaveLength(1);
    });

    it("should return false when user has no backup codes", async () => {
      // No generateBackupCodes call — backupCodes is undefined.
      const ok = await svc.consumeBackupCode("alice", "ZZZZ-ZZZZ-ZZ");
      expect(ok).toBe(false);
    });

    it("should throw NOT_FOUND when consuming for an unknown user", async () => {
      try {
        await svc.consumeBackupCode("unknown", "ANY-CODE-HE");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });
  });

  describe("verifyMfa", () => {
    let mfaSvc: UserService;
    let secret: string;

    beforeEach(async () => {
      mfaSvc = new UserService(store, {
        password: { ...FAST_SCRYPT },
        lockout: { threshold: 3, duration: 60000 },
        clock: () => now,
      });
      await createActiveUser(mfaSvc, "alice", "pass123");
      secret = generateTotpSecret();
      await mfaSvc.addMfaMethod("alice", { name: "totp", confirmed: true, value: secret });
    });

    it("should accept a valid TOTP code", async () => {
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa("alice", code, { clock: () => now });
    });

    it("should throw MFA_INVALID on a wrong code", async () => {
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_INVALID");
      }
    });

    it("should throw MFA_NOT_CONFIGURED when user has no confirmed TOTP", async () => {
      await mfaSvc.removeMfaMethod("alice", "totp");
      try {
        await mfaSvc.verifyMfa("alice", "123456", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_NOT_CONFIGURED");
      }
    });

    it("should increment failedLoginAttempts on wrong code", async () => {
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa("alice", "111111", { clock: () => now });
      } catch {}
      const user = await mfaSvc.getUser("alice");
      expect(user.account.failedLoginAttempts).toBe(2);
    });

    it("should lock the account after threshold MFA failures", async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
        } catch {}
      }
      const user = await mfaSvc.getUser("alice");
      expect(user.account.locked).toBe(true);
      expect(user.account.lockReason).toBe("Too many login attempts");
      expect(user.account.lockEnds).toBe(now + 60000);
    });

    it("should surface lockEnds in MFA_INVALID details when the failure trips the lock", async () => {
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_INVALID");
        expect((e as UserAuthError).details?.lockEnds).toBe(now + 60000);
      }
    });

    it("should throw LOCKED on subsequent attempts when account is already locked", async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
        } catch {}
      }
      try {
        await mfaSvc.verifyMfa("alice", "999999", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("LOCKED");
      }
    });

    it("should reset failedLoginAttempts on successful verification", async () => {
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa("alice", "111111", { clock: () => now });
      } catch {}
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa("alice", code, { clock: () => now });
      const user = await mfaSvc.getUser("alice");
      expect(user.account.failedLoginAttempts).toBe(0);
    });

    it("should share the failure counter with login (one threshold across both factors)", async () => {
      // Two wrong passwords + one wrong MFA = 3 total → lock.
      try {
        await mfaSvc.login("alice", "wrong");
      } catch {}
      try {
        await mfaSvc.login("alice", "wrong");
      } catch {}
      try {
        await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
      } catch {}
      const user = await mfaSvc.getUser("alice");
      expect(user.account.locked).toBe(true);
    });

    it("should auto-unlock after lock duration expires before verifying", async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await mfaSvc.verifyMfa("alice", "000000", { clock: () => now });
        } catch {}
      }
      now += 61000;
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa("alice", code, { clock: () => now });
      const user = await mfaSvc.getUser("alice");
      expect(user.account.locked).toBe(false);
    });

    it("should throw NOT_FOUND for unknown user", async () => {
      try {
        await mfaSvc.verifyMfa("unknown", "123456", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });

    it("rejects a same-window TOTP replay (RFC 6238 SHOULD)", async () => {
      // An attacker who observes a freshly-used code (network sniff, malicious
      // browser ext, shoulder-surf) must not be able to reuse it within the
      // live 30 s window. The replay surfaces as MFA_INVALID — same UX as a
      // wrong code, so we don't leak "replayed" vs "wrong" to the attacker.
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa("alice", code, { clock: () => now });
      try {
        await mfaSvc.verifyMfa("alice", code, { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_INVALID");
      }
      const user = await mfaSvc.getUser("alice");
      expect(user.account.failedLoginAttempts).toBe(1);
    });
  });

  describe("trustedDevices", () => {
    let dtNow: number;
    let dtStore: UserStoreMemory;
    let dtSvc: UserService;

    beforeEach(async () => {
      dtNow = 1000000;
      dtStore = new UserStoreMemory();
      dtSvc = new UserService(dtStore, {
        password: { ...FAST_SCRYPT },
        clock: () => dtNow,
        deviceTrust: { secret: "unit-test-secret" },
      });
      await createActiveUser(dtSvc, "alice", "Password1!");
    });

    it("issueTrustedDevice + addTrustedDevice + verifyTrustedDevice round-trips (no IP)", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice("alice", rec);
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token)).toBe(true);
    });

    it("issueTrustedDevice + verifyTrustedDevice round-trips with IP binding", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000, ip: "10.0.0.1" });
      await dtSvc.addTrustedDevice("alice", rec);
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token, "10.0.0.1")).toBe(true);
      // Wrong IP rejected — HMAC payload differs AND record IP differs.
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token, "10.0.0.2")).toBe(false);
    });

    it("verifyTrustedDevice returns false for a forged signature", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice("alice", rec);
      const [raw] = rec.token.split(".");
      const fake = `${raw}.${"0".repeat(64)}`;
      expect(await dtSvc.verifyTrustedDevice("alice", fake)).toBe(false);
    });

    it("verifyTrustedDevice returns false when token signature is valid but no record persisted", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      // NB: NOT calling addTrustedDevice — signature would verify but record is absent.
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token)).toBe(false);
    });

    it("verifyTrustedDevice returns false after expiry (clock advanced past expiresAt)", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice("alice", rec);
      dtNow += 60_001;
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token)).toBe(false);
    });

    it("revokeTrustedDevice removes the matching record (subsequent verify false)", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice("alice", rec);
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token)).toBe(true);
      await dtSvc.revokeTrustedDevice("alice", rec.token);
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token)).toBe(false);
    });

    it("revokeTrustedDevice is a no-op for an unknown token (does not throw, leaves siblings)", async () => {
      const rec = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice("alice", rec);
      await dtSvc.revokeTrustedDevice("alice", "no-such-token.sig");
      expect(await dtSvc.verifyTrustedDevice("alice", rec.token)).toBe(true);
    });

    it("listTrustedDevices returns all persisted records in insertion order", async () => {
      const r1 = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000, name: "macbook" });
      await dtSvc.addTrustedDevice("alice", r1);
      const r2 = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000, name: "phone" });
      await dtSvc.addTrustedDevice("alice", r2);
      const list = await dtSvc.listTrustedDevices("alice");
      expect(list.length).toBe(2);
      expect(list[0].name).toBe("macbook");
      expect(list[1].name).toBe("phone");
    });

    it("REGRESSION — concurrent addTrustedDevice must not lose a record", async () => {
      // Two devices opting in to "remember me" at the same instant: both
      // records must land. Pre-OCC the read-modify-write of trustedDevices[]
      // could drop one because both reads saw the empty list.
      const r1 = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000, name: "macbook" });
      const r2 = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000, name: "phone" });
      await Promise.all([dtSvc.addTrustedDevice("alice", r1), dtSvc.addTrustedDevice("alice", r2)]);
      const list = await dtSvc.listTrustedDevices("alice");
      const names = list.map((r) => r.name);
      expect(names).toHaveLength(2);
      expect(names).toContain("macbook");
      expect(names).toContain("phone");
    });

    it("issueTrustedDevice throws clearly when deviceTrust.secret is not configured", () => {
      const noSecretSvc = new UserService(new UserStoreMemory(), {
        password: { ...FAST_SCRYPT },
      });
      expect(() => noSecretSvc.issueTrustedDevice("alice", { ttlMs: 60_000 })).toThrow(
        /deviceTrust\.secret/,
      );
    });

    it("verifyTrustedDevice throws clearly when deviceTrust.secret is not configured", async () => {
      const noSecretSvc = new UserService(new UserStoreMemory(), {
        password: { ...FAST_SCRYPT },
      });
      await expect(noSecretSvc.verifyTrustedDevice("alice", "x.y")).rejects.toThrow(
        /deviceTrust\.secret/,
      );
    });

    it("HMAC depends on the secret — a record signed by one secret cannot be verified by another", async () => {
      const recA = dtSvc.issueTrustedDevice("alice", { ttlMs: 60_000 });
      const otherSvc = new UserService(dtStore, {
        password: { ...FAST_SCRYPT },
        clock: () => dtNow,
        deviceTrust: { secret: "different-secret" },
      });
      await dtSvc.addTrustedDevice("alice", recA);
      expect(await otherSvc.verifyTrustedDevice("alice", recA.token)).toBe(false);
    });
  });
});
