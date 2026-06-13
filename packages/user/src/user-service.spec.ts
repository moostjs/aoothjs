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
  await svc.activateAccount(user.id);
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
      expect(await svc.verifyPassword(user.id, "MyPassword1!")).toBe(true);
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

    // `createUser` now mints a stable surrogate `id` (a server-managed UUID,
    // also the token subject) and stamps it onto the record handed to the
    // store, so callers can `auth.issue(user.id)` without a re-read. The
    // contract being verified: `createUser` DOES put a non-empty `id` on the
    // record when the caller does not supply one.
    it("mints a non-empty `id` on the record passed to store.create when no id is supplied", async () => {
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
      const user = await recSvc.createUser("alice", "pass123");
      expect(received).toBeDefined();
      expect("id" in (received as object)).toBe(true);
      expect(typeof received!.id).toBe("string");
      expect((received!.id as string).length).toBeGreaterThan(0);
      // The minted id is the one returned on the record.
      expect(received!.id).toBe(user.id);
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
      const created = await svc.createUser("alice");
      const user = await svc.getUser(created.id);
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
      const alice = await createActiveUser(svc, "alice", "pass123");
      try {
        await svc.login("alice", "wrong");
      } catch {}
      try {
        await svc.login("alice", "wrong");
      } catch {}
      const user = await svc.getUser(alice.id);
      expect(user.account.failedLoginAttempts).toBe(2);
    });

    it("should reset failedLoginAttempts on success", async () => {
      const alice = await createActiveUser(svc, "alice", "pass123");
      try {
        await svc.login("alice", "wrong");
      } catch {}
      await svc.login("alice", "pass123");
      const user = await svc.getUser(alice.id);
      expect(user.account.failedLoginAttempts).toBe(0);
    });

    it("should indicate mfaRequired when MFA methods are confirmed", async () => {
      const alice = await createActiveUser(svc, "alice", "pass123");
      await svc.addMfaMethod(alice.id, {
        name: "totp",
        confirmed: true,
        value: "ABCDEF",
      });
      const result = await svc.login("alice", "pass123");
      expect(result.mfaRequired).toBe(true);
    });
  });

  describe("recordLogin", () => {
    it("should stamp lastLogin and return the timestamp", async () => {
      const alice = await createActiveUser(svc, "alice", "pass123");
      const stamped = await svc.recordLogin(alice.id);
      expect(stamped).toBe(now);
      const user = await svc.getUser(alice.id);
      expect(user.account.lastLogin).toBe(now);
    });

    it("should reset failedLoginAttempts to 0", async () => {
      const alice = await createActiveUser(svc, "alice", "pass123");
      try {
        await svc.login("alice", "wrong");
      } catch {}
      await svc.recordLogin(alice.id);
      const user = await svc.getUser(alice.id);
      expect(user.account.failedLoginAttempts).toBe(0);
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
      const alice = await createActiveUser(lockSvc, "alice", "pass123");
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const user = await lockSvc.getUser(alice.id);
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

    // WHY (Rule 9): the per-call `lockoutOverride` is the bridge that lets a
    // workflow policy resolver pick the lock POSTURE per request (the
    // admin-only / self-service / temporary modes) without reconstructing
    // UserService. Here the service is configured TEMPORARY (duration 60s) but
    // the caller forces a PERMANENT lock for this attempt — the override must
    // win, so the lock never auto-expires. A regression that ignored the
    // override (used config.duration) would auto-unlock after 60s and silently
    // downgrade an admin-only/self-service policy to temporary.
    it("per-call lockoutOverride forces a permanent lock even when config is temporary", async () => {
      const alice = await createActiveUser(lockSvc, "alice", "pass123"); // lockSvc: duration 60_000
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong", { duration: 0 });
        } catch {}
      }
      const locked = await lockSvc.getUser(alice.id);
      expect(locked.account.locked).toBe(true);
      expect(locked.account.lockEnds).toBe(0); // 0 = permanent, not now+60_000

      // Past the would-be temporary window: still locked (override held).
      now += 61000;
      try {
        await lockSvc.login("alice", "pass123");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("LOCKED");
      }
    });

    // Inverse: with no override the service's own temporary duration applies,
    // so the same threshold trip yields a timed lock that DOES auto-expire.
    // Pins that the override is opt-in and doesn't change the default path.
    it("without an override the lock uses the configured temporary duration", async () => {
      const alice = await createActiveUser(lockSvc, "alice", "pass123");
      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const locked = await lockSvc.getUser(alice.id);
      expect(locked.account.lockEnds).toBe(now + 60000);
    });
  });

  describe("lockout — case sensitivity invariant", () => {
    // WHY: `findByHandle` and the lockout key are both case-sensitive today
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
      const lowerUser = await createActiveUser(lockSvc, "alice", "pass123");
      const upperUser = await createActiveUser(lockSvc, "Alice", "pass123");

      for (let i = 0; i < 3; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const lower = await lockSvc.getUser(lowerUser.id);
      expect(lower.account.locked).toBe(true);

      // `Alice` must still authenticate cleanly with her own credentials.
      const result = await lockSvc.login("Alice", "pass123");
      expect(result.user.username).toBe("Alice");
      const upper = await lockSvc.getUser(upperUser.id);
      expect(upper.account.locked).toBe(false);
      expect(upper.account.failedLoginAttempts).toBe(0);
    });

    it("case-variant probing of a non-existent account does NOT inflate the real account's lockout budget", async () => {
      // Seed only `alice` (lowercase). `Alice` does not exist.
      const alice = await createActiveUser(lockSvc, "alice", "pass123");

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
      const before = await lockSvc.getUser(alice.id);
      expect(before.account.failedLoginAttempts).toBe(0);
      expect(before.account.locked).toBe(false);

      // Now drive `alice` to (threshold - 1) bad attempts: she must STILL be
      // unlocked — proving the variant probes didn't pre-charge her counter.
      for (let i = 0; i < 2; i++) {
        try {
          await lockSvc.login("alice", "wrong");
        } catch {}
      }
      const mid = await lockSvc.getUser(alice.id);
      expect(mid.account.locked).toBe(false);
      expect(mid.account.failedLoginAttempts).toBe(2);

      // The Nth (threshold) bad alice-attempt must trip the lock — exactly N,
      // not 2N. If the variant probes had counted, this would have fired earlier.
      try {
        await lockSvc.login("alice", "wrong");
      } catch {}
      const locked = await lockSvc.getUser(alice.id);
      expect(locked.account.locked).toBe(true);
    });
  });

  describe("changePassword", () => {
    it("should change password with correct current password", async () => {
      const alice = await svc.createUser("alice", "oldpass");
      await svc.changePassword(alice.id, "oldpass", "newpass");
      expect(await svc.verifyPassword(alice.id, "newpass")).toBe(true);
      expect(await svc.verifyPassword(alice.id, "oldpass")).toBe(false);
    });

    it("should throw INVALID_CREDENTIALS for wrong current password", async () => {
      const alice = await svc.createUser("alice", "oldpass");
      try {
        await svc.changePassword(alice.id, "wrong", "newpass");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("INVALID_CREDENTIALS");
      }
    });

    it("should throw PASSWORDS_MISMATCH when repeat doesn't match", async () => {
      const alice = await svc.createUser("alice", "oldpass");
      try {
        await svc.changePassword(alice.id, "oldpass", "newpass", "different");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("PASSWORDS_MISMATCH");
      }
    });

    it("should throw PASSWORD_IN_HISTORY for current password reuse", async () => {
      const alice = await svc.createUser("alice", "mypass");
      try {
        await svc.changePassword(alice.id, "mypass", "mypass");
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
      const alice = await historySvc.createUser("alice", "pass1");
      await historySvc.changePassword(alice.id, "pass1", "pass2");
      await historySvc.changePassword(alice.id, "pass2", "pass3");

      // pass1 should be in history
      try {
        await historySvc.changePassword(alice.id, "pass3", "pass1");
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
      const alice = await policySvc.createUser("alice", "OldPass1!");
      try {
        await policySvc.changePassword(alice.id, "OldPass1!", "short");
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
      const alice = await svc.createUser("alice", "oldpass");
      await svc.setPassword(alice.id, "newpass");
      expect(await svc.verifyPassword(alice.id, "newpass")).toBe(true);
    });
  });

  describe("account management", () => {
    it("should activate account", async () => {
      const alice = await svc.createUser("alice");
      await svc.activateAccount(alice.id);
      const user = await svc.getUser(alice.id);
      expect(user.account.active).toBe(true);
    });

    it("should deactivate account", async () => {
      const alice = await svc.createUser("alice");
      await svc.activateAccount(alice.id);
      await svc.deactivateAccount(alice.id);
      const user = await svc.getUser(alice.id);
      expect(user.account.active).toBe(false);
    });

    it("should lock account with reason and duration", async () => {
      const alice = await svc.createUser("alice");
      await svc.lockAccount(alice.id, "Suspicious activity", 60000);
      const user = await svc.getUser(alice.id);
      expect(user.account.locked).toBe(true);
      expect(user.account.lockReason).toBe("Suspicious activity");
      expect(user.account.lockEnds).toBe(now + 60000);
    });

    it("should lock permanently when no duration", async () => {
      const alice = await svc.createUser("alice");
      await svc.lockAccount(alice.id, "Banned");
      const user = await svc.getUser(alice.id);
      expect(user.account.locked).toBe(true);
      expect(user.account.lockEnds).toBe(0);
    });

    it("should unlock account and reset failed attempts", async () => {
      const alice = await svc.createUser("alice");
      await svc.lockAccount(alice.id, "test");
      await svc.unlockAccount(alice.id);
      const user = await svc.getUser(alice.id);
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
    let aliceId: string;

    beforeEach(async () => {
      const alice = await svc.createUser("alice", "pass123");
      aliceId = alice.id;
    });

    it("should add an MFA method", async () => {
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: false, value: "alice@test.com" });
      const user = await svc.getUser(aliceId);
      const method = user.mfa.methods.find((m) => m.name === "email");
      expect(method).toBeDefined();
      expect(method!.confirmed).toBe(false);
      expect(method!.value).toBe("alice@test.com");
    });

    it("should replace existing method with same name", async () => {
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: false, value: "old@test.com" });
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: false, value: "new@test.com" });
      const user = await svc.getUser(aliceId);
      expect(user.mfa.methods.filter((m) => m.name === "email")).toHaveLength(1);
      expect(user.mfa.methods.find((m) => m.name === "email")!.value).toBe("new@test.com");
    });

    it("should confirm an MFA method", async () => {
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: false, value: "alice@test.com" });
      await svc.confirmMfaMethod(aliceId, "email");
      const user = await svc.getUser(aliceId);
      expect(user.mfa.methods.find((m) => m.name === "email")!.confirmed).toBe(true);
    });

    it("should throw MFA_NOT_CONFIGURED for unknown method", async () => {
      try {
        await svc.confirmMfaMethod(aliceId, "nonexistent");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_NOT_CONFIGURED");
      }
    });

    it("should remove an MFA method", async () => {
      await svc.addMfaMethod(aliceId, { name: "totp", confirmed: true, value: "ABC" });
      await svc.removeMfaMethod(aliceId, "totp");
      const user = await svc.getUser(aliceId);
      expect(user.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();
    });

    it("should clear defaultMethod when removing the default method", async () => {
      await svc.addMfaMethod(aliceId, { name: "totp", confirmed: true, value: "ABC" });
      await svc.setDefaultMfaMethod(aliceId, "totp");
      await svc.removeMfaMethod(aliceId, "totp");
      const user = await svc.getUser(aliceId);
      expect(user.mfa.defaultMethod).toBe("");
    });

    it("should set default MFA method", async () => {
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: true, value: "a@b.c" });
      await svc.setDefaultMfaMethod(aliceId, "email");
      const user = await svc.getUser(aliceId);
      expect(user.mfa.defaultMethod).toBe("email");
      expect(user.mfa.autoSend).toBe(false);
    });

    it("should throw MFA_NOT_CONFIGURED for setting non-existent default", async () => {
      try {
        await svc.setDefaultMfaMethod(aliceId, "nonexistent");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_NOT_CONFIGURED");
      }
    });

    it("should get available (confirmed) MFA methods", async () => {
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: true, value: "alice@test.com" });
      await svc.addMfaMethod(aliceId, { name: "totp", confirmed: false, value: "ABC" });
      const user = await svc.getUser(aliceId);
      const methods = svc.getAvailableMfaMethods(user.mfa);
      expect(methods).toHaveLength(1);
      expect(methods[0].name).toBe("email");
      expect(methods[0].masked).toContain("***");
    });

    it("should set MFA autoSend", async () => {
      await svc.setMfaAutoSend(aliceId, true);
      const user = await svc.getUser(aliceId);
      expect(user.mfa.autoSend).toBe(true);
    });

    it("REGRESSION — concurrent addMfaMethod must not lose a method", async () => {
      // Two devices enrolling different MFA factors at the same time must
      // both land — the read-modify-write of mfa.methods[] used to drop one.
      await Promise.all([
        svc.addMfaMethod(aliceId, { name: "totp", confirmed: false, value: "SECRET" }),
        svc.addMfaMethod(aliceId, { name: "email", confirmed: false, value: "alice@test.com" }),
      ]);
      const user = await svc.getUser(aliceId);
      expect(user.mfa.methods.map((m) => m.name).toSorted((a, b) => a.localeCompare(b))).toEqual([
        "email",
        "totp",
      ]);
    });

    it("REGRESSION — concurrent confirmMfaMethod must not race with addMfaMethod", async () => {
      // User adds totp via one tab while confirming a pre-existing email
      // factor in another. Both writes must compose — confirming email
      // shouldn't wipe the newly-added totp from the methods array.
      await svc.addMfaMethod(aliceId, { name: "email", confirmed: false, value: "alice@test.com" });
      await Promise.all([
        svc.addMfaMethod(aliceId, { name: "totp", confirmed: false, value: "SECRET" }),
        svc.confirmMfaMethod(aliceId, "email"),
      ]);
      const user = await svc.getUser(aliceId);
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
      const alice = await svc.createUser("alice");
      const before = await svc.getUser(alice.id);
      expect(before.password.isInitial).toBe(true);

      now += 1000;
      await svc.setPassword(alice.id, "newpass123");
      const after = await svc.getUser(alice.id);
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
      const alice = await createActiveUser(svc, "alice", "pass123");
      await svc.addMfaMethod(alice.id, { name: "totp", confirmed: false, value: "SECRET" });
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

  describe("verifyMfa", () => {
    let mfaSvc: UserService;
    let secret: string;
    let aliceId: string;

    beforeEach(async () => {
      mfaSvc = new UserService(store, {
        password: { ...FAST_SCRYPT },
        lockout: { threshold: 3, duration: 60000 },
        clock: () => now,
      });
      const alice = await createActiveUser(mfaSvc, "alice", "pass123");
      aliceId = alice.id;
      secret = generateTotpSecret();
      await mfaSvc.addMfaMethod(aliceId, { name: "totp", confirmed: true, value: secret });
    });

    it("should accept a valid TOTP code", async () => {
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa(aliceId, code, { clock: () => now });
    });

    it("should throw MFA_INVALID on a wrong code", async () => {
      try {
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_INVALID");
      }
    });

    it("should throw MFA_NOT_CONFIGURED when user has no confirmed TOTP", async () => {
      await mfaSvc.removeMfaMethod(aliceId, "totp");
      try {
        await mfaSvc.verifyMfa(aliceId, "123456", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_NOT_CONFIGURED");
      }
    });

    it("should increment failedLoginAttempts on wrong code", async () => {
      try {
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa(aliceId, "111111", { clock: () => now });
      } catch {}
      const user = await mfaSvc.getUser(aliceId);
      expect(user.account.failedLoginAttempts).toBe(2);
    });

    it("should lock the account after threshold MFA failures", async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
        } catch {}
      }
      const user = await mfaSvc.getUser(aliceId);
      expect(user.account.locked).toBe(true);
      expect(user.account.lockReason).toBe("Too many login attempts");
      expect(user.account.lockEnds).toBe(now + 60000);
    });

    it("should surface lockEnds in MFA_INVALID details when the failure trips the lock", async () => {
      try {
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_INVALID");
        expect((e as UserAuthError).details?.lockEnds).toBe(now + 60000);
      }
    });

    it("should throw LOCKED on subsequent attempts when account is already locked", async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
        } catch {}
      }
      try {
        await mfaSvc.verifyMfa(aliceId, "999999", { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("LOCKED");
      }
    });

    it("should reset failedLoginAttempts on successful verification", async () => {
      try {
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
      } catch {}
      try {
        await mfaSvc.verifyMfa(aliceId, "111111", { clock: () => now });
      } catch {}
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa(aliceId, code, { clock: () => now });
      const user = await mfaSvc.getUser(aliceId);
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
        await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
      } catch {}
      const user = await mfaSvc.getUser(aliceId);
      expect(user.account.locked).toBe(true);
    });

    it("should auto-unlock after lock duration expires before verifying", async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await mfaSvc.verifyMfa(aliceId, "000000", { clock: () => now });
        } catch {}
      }
      now += 61000;
      const code = generateTotpCode(secret, { clock: () => now });
      await mfaSvc.verifyMfa(aliceId, code, { clock: () => now });
      const user = await mfaSvc.getUser(aliceId);
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
      await mfaSvc.verifyMfa(aliceId, code, { clock: () => now });
      try {
        await mfaSvc.verifyMfa(aliceId, code, { clock: () => now });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("MFA_INVALID");
      }
      const user = await mfaSvc.getUser(aliceId);
      expect(user.account.failedLoginAttempts).toBe(1);
    });
  });

  /** Shared fixture for the trust + recognition suites: secret-configured
   * service over `store` with a test-controlled clock. */
  function makeDeviceSvc(store: UserStoreMemory, clock: () => number): UserService {
    return new UserService(store, {
      password: { ...FAST_SCRYPT },
      clock,
      deviceTrust: { secret: "unit-test-secret" },
    });
  }

  describe("trustedDevices", () => {
    let dtNow: number;
    let dtStore: UserStoreMemory;
    let dtSvc: UserService;
    let aliceId: string;

    beforeEach(async () => {
      dtNow = 1000000;
      dtStore = new UserStoreMemory();
      dtSvc = makeDeviceSvc(dtStore, () => dtNow);
      const alice = await createActiveUser(dtSvc, "alice", "Password1!");
      aliceId = alice.id;
    });

    it("issueTrustedDevice + addTrustedDevice + verifyTrustedDevice round-trips (no IP)", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice(aliceId, rec);
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token)).toBe(true);
    });

    it("issueTrustedDevice + verifyTrustedDevice round-trips with IP binding", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000, ip: "10.0.0.1" });
      await dtSvc.addTrustedDevice(aliceId, rec);
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token, "10.0.0.1")).toBe(true);
      // Wrong IP rejected — HMAC payload differs AND record IP differs.
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token, "10.0.0.2")).toBe(false);
    });

    it("verifyTrustedDevice returns false for a forged signature", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice(aliceId, rec);
      const [raw] = rec.token.split(".");
      const fake = `${raw}.${"0".repeat(64)}`;
      expect(await dtSvc.verifyTrustedDevice(aliceId, fake)).toBe(false);
    });

    it("verifyTrustedDevice returns false when token signature is valid but no record persisted", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      // NB: NOT calling addTrustedDevice — signature would verify but record is absent.
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token)).toBe(false);
    });

    it("verifyTrustedDevice returns false after expiry (clock advanced past expiresAt)", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice(aliceId, rec);
      dtNow += 60_001;
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token)).toBe(false);
    });

    it("revokeTrustedDevice removes the matching record (subsequent verify false)", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice(aliceId, rec);
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token)).toBe(true);
      await dtSvc.revokeTrustedDevice(aliceId, rec.token);
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token)).toBe(false);
    });

    it("revokeTrustedDevice is a no-op for an unknown token (does not throw, leaves siblings)", async () => {
      const rec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice(aliceId, rec);
      await dtSvc.revokeTrustedDevice(aliceId, "no-such-token.sig");
      expect(await dtSvc.verifyTrustedDevice(aliceId, rec.token)).toBe(true);
    });

    it("listTrustedDevices returns all persisted records in insertion order", async () => {
      const r1 = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000, name: "macbook" });
      await dtSvc.addTrustedDevice(aliceId, r1);
      const r2 = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000, name: "phone" });
      await dtSvc.addTrustedDevice(aliceId, r2);
      const list = await dtSvc.listTrustedDevices(aliceId);
      expect(list.length).toBe(2);
      expect(list[0].name).toBe("macbook");
      expect(list[1].name).toBe("phone");
    });

    it("REGRESSION — concurrent addTrustedDevice must not lose a record", async () => {
      // Two devices opting in to "remember me" at the same instant: both
      // records must land. Pre-OCC the read-modify-write of trustedDevices[]
      // could drop one because both reads saw the empty list.
      const r1 = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000, name: "macbook" });
      const r2 = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000, name: "phone" });
      await Promise.all([dtSvc.addTrustedDevice(aliceId, r1), dtSvc.addTrustedDevice(aliceId, r2)]);
      const list = await dtSvc.listTrustedDevices(aliceId);
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
      const recA = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      const otherSvc = new UserService(dtStore, {
        password: { ...FAST_SCRYPT },
        clock: () => dtNow,
        deviceTrust: { secret: "different-secret" },
      });
      await dtSvc.addTrustedDevice(aliceId, recA);
      expect(await otherSvc.verifyTrustedDevice(aliceId, recA.token)).toBe(false);
    });
  });

  describe("seenDevices", () => {
    let dtNow: number;
    let dtStore: UserStoreMemory;
    let dtSvc: UserService;
    let aliceId: string;

    beforeEach(async () => {
      dtNow = 1000000;
      dtStore = new UserStoreMemory();
      dtSvc = makeDeviceSvc(dtStore, () => dtNow);
      const alice = await createActiveUser(dtSvc, "alice", "Password1!");
      aliceId = alice.id;
    });

    it("issueSeenDevice + addSeenDevice + verifySeenDevice round-trips (no slide)", async () => {
      const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addSeenDevice(aliceId, rec);
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token)).toBe(true);
    });

    it("verifySeenDevice returns false for a forged signature", async () => {
      const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addSeenDevice(aliceId, rec);
      const [raw] = rec.token.split(".");
      const fake = `${raw}.${"0".repeat(64)}`;
      expect(await dtSvc.verifySeenDevice(aliceId, fake)).toBe(false);
    });

    it("verifySeenDevice returns false when token signature is valid but no record persisted", async () => {
      const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      // NB: NOT calling addSeenDevice — signature would verify but record is absent.
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token)).toBe(false);
    });

    it("domain separation — a TRUST token never verifies as a SEEN token, and vice versa", async () => {
      // The two ledgers carry different stakes (MFA bypass vs notification
      // suppression); a leaked recognition cookie must never unlock trust.
      const trustRec = dtSvc.issueTrustedDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addTrustedDevice(aliceId, trustRec);
      expect(await dtSvc.verifySeenDevice(aliceId, trustRec.token)).toBe(false);

      const seenRec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addSeenDevice(aliceId, seenRec);
      expect(await dtSvc.verifyTrustedDevice(aliceId, seenRec.token)).toBe(false);
    });

    it("verifySeenDevice returns false after expiry (clock advanced past expiresAt)", async () => {
      const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addSeenDevice(aliceId, rec);
      dtNow += 60_001;
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token)).toBe(false);
    });

    it("slideTtlMs slides expiry — token outlives its ORIGINAL expiresAt after a verified hit", async () => {
      const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addSeenDevice(aliceId, rec);
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token, { slideTtlMs: 120_000 })).toBe(true);
      // Past the original window (issuedAt + 60s) but inside the slid one.
      dtNow += 90_000;
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token)).toBe(true);
    });

    it("cap + LRU eviction — 6th add evicts the smallest-expiresAt record, 5 most-recent survive", async () => {
      const records = [];
      for (let i = 0; i < 6; i++) {
        // Distinct expiresAt per record: each later add expires later.
        const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 + i * 1000, name: `dev-${i}` });
        records.push(rec);
        await dtSvc.addSeenDevice(aliceId, rec);
      }
      const list = await dtSvc.listSeenDevices(aliceId);
      expect(list.length).toBe(5);
      const names = list.map((r) => r.name);
      expect(names).not.toContain("dev-0"); // least-recently-verified evicted
      for (let i = 1; i < 6; i++) expect(names).toContain(`dev-${i}`);
    });

    it("cap enforcement drops EXPIRED records before evicting healthy ones", async () => {
      // 5 healthy + 1 expired = over cap; the expired one must go first,
      // leaving all 5 healthy records intact.
      const shortLived = dtSvc.issueSeenDevice(aliceId, { ttlMs: 1000, name: "stale" });
      await dtSvc.addSeenDevice(aliceId, shortLived);
      dtNow += 2000; // shortLived is now expired
      for (let i = 0; i < 5; i++) {
        const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 + i * 1000, name: `dev-${i}` });
        await dtSvc.addSeenDevice(aliceId, rec);
      }
      const list = await dtSvc.listSeenDevices(aliceId);
      expect(list.length).toBe(5);
      const names = list.map((r) => r.name);
      expect(names).not.toContain("stale");
      for (let i = 0; i < 5; i++) expect(names).toContain(`dev-${i}`);
    });

    it("revokeSeenDevices clears the whole ledger — subsequent verify false", async () => {
      const rec = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000 });
      await dtSvc.addSeenDevice(aliceId, rec);
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token)).toBe(true);
      await dtSvc.revokeSeenDevices(aliceId);
      expect(await dtSvc.verifySeenDevice(aliceId, rec.token)).toBe(false);
      expect(await dtSvc.listSeenDevices(aliceId)).toEqual([]);
    });

    it("revokeSeenDevices is a no-op on a user with no ledger (does not throw)", async () => {
      await dtSvc.revokeSeenDevices(aliceId);
      expect(await dtSvc.listSeenDevices(aliceId)).toEqual([]);
    });

    it("issueSeenDevice throws clearly when deviceTrust.secret is not configured", () => {
      const noSecretSvc = new UserService(new UserStoreMemory(), {
        password: { ...FAST_SCRYPT },
      });
      expect(() => noSecretSvc.issueSeenDevice("alice", { ttlMs: 60_000 })).toThrow(
        /deviceTrust\.secret/,
      );
    });

    it("verifySeenDevice throws clearly when deviceTrust.secret is not configured", async () => {
      const noSecretSvc = new UserService(new UserStoreMemory(), {
        password: { ...FAST_SCRYPT },
      });
      await expect(noSecretSvc.verifySeenDevice("alice", "x.y")).rejects.toThrow(
        /deviceTrust\.secret/,
      );
    });

    it("hasDeviceTrustSecret lets the workflow layer degrade gracefully (false without, true with)", () => {
      const noSecretSvc = new UserService(new UserStoreMemory(), {
        password: { ...FAST_SCRYPT },
      });
      expect(noSecretSvc.hasDeviceTrustSecret()).toBe(false);
      expect(dtSvc.hasDeviceTrustSecret()).toBe(true);
    });

    it("REGRESSION — concurrent addSeenDevice must not lose a record (CAS)", async () => {
      // Two logins from different devices at the same instant: both
      // recognition records must land despite the read-modify-write.
      const r1 = dtSvc.issueSeenDevice(aliceId, { ttlMs: 60_000, name: "macbook" });
      const r2 = dtSvc.issueSeenDevice(aliceId, { ttlMs: 61_000, name: "phone" });
      await Promise.all([dtSvc.addSeenDevice(aliceId, r1), dtSvc.addSeenDevice(aliceId, r2)]);
      const names = (await dtSvc.listSeenDevices(aliceId)).map((r) => r.name);
      expect(names).toHaveLength(2);
      expect(names).toContain("macbook");
      expect(names).toContain("phone");
    });
  });

  describe("correspondence email", () => {
    describe("setVerifiedEmail", () => {
      it("round-trips through getUser and survives alongside other account fields", async () => {
        const alice = await createActiveUser(svc, "alice", "pass123");
        await svc.login("alice", "pass123"); // stamps account.lastLogin
        await svc.setVerifiedEmail(alice.id, "proved@example.com");
        const user = await svc.getUser(alice.id);
        expect(user.account.verifiedEmail).toBe("proved@example.com");
        // Deep-merge: sibling account fields untouched.
        expect(user.account.active).toBe(true);
        expect(user.account.lastLogin).toBe(now);
      });

      it("overwrites the previous address on a later inbox proof", async () => {
        const alice = await createActiveUser(svc, "alice", "pass123");
        await svc.setVerifiedEmail(alice.id, "first@example.com");
        await svc.setVerifiedEmail(alice.id, "second@example.com");
        const user = await svc.getUser(alice.id);
        expect(user.account.verifiedEmail).toBe("second@example.com");
      });

      it("should throw NOT_FOUND for unknown user", async () => {
        try {
          await svc.setVerifiedEmail("unknown", "x@example.com");
          expect.unreachable();
        } catch (e) {
          expect((e as UserAuthError).type).toBe("NOT_FOUND");
        }
      });
    });

    describe("getCorrespondenceEmail", () => {
      type Extras = { contactEmail?: string };
      let emailStore: UserStoreMemory<Extras>;
      let emailSvc: UserService<Extras>;

      beforeEach(() => {
        emailStore = new UserStoreMemory<Extras>();
        emailSvc = new UserService<Extras>(emailStore, {
          password: { ...FAST_SCRYPT },
          clock: () => now,
          emailField: "contactEmail",
        });
      });

      it("PROVEN-first: verifiedEmail beats both the MFA method and the emailField column", async () => {
        const alice = await emailSvc.createUser("alice", "pass123", {
          contactEmail: "column@example.com",
        });
        await emailSvc.setVerifiedEmail(alice.id, "proved@example.com");
        await emailSvc.addMfaMethod(alice.id, {
          name: "email",
          confirmed: true,
          value: "mfa@example.com",
        });
        const user = await emailSvc.getUser(alice.id);
        expect(await emailSvc.getCorrespondenceEmail(user)).toBe("proved@example.com");
      });

      it("confirmed email MFA (also proven) beats the UNPROVEN column when verifiedEmail is absent", async () => {
        const alice = await emailSvc.createUser("alice", "pass123", {
          contactEmail: "column@example.com",
        });
        await emailSvc.addMfaMethod(alice.id, {
          name: "email",
          confirmed: true,
          value: "mfa@example.com",
        });
        const user = await emailSvc.getUser(alice.id);
        expect(await emailSvc.getCorrespondenceEmail(user)).toBe("mfa@example.com");
      });

      it("falls back to the emailField column as the last resort (app-canonical, unproven)", async () => {
        const alice = await emailSvc.createUser("alice", "pass123", {
          contactEmail: "column@example.com",
        });
        const user = await emailSvc.getUser(alice.id);
        expect(await emailSvc.getCorrespondenceEmail(user)).toBe("column@example.com");
      });

      it("empty-string column never satisfies the chain", async () => {
        const alice = await emailSvc.createUser("alice", "pass123", { contactEmail: "" });
        const user = await emailSvc.getUser(alice.id);
        expect(await emailSvc.getCorrespondenceEmail(user)).toBeUndefined();
      });

      it("ignores an UNCONFIRMED email MFA method (confirmed-only) — undefined", async () => {
        const alice = await emailSvc.createUser("alice", "pass123");
        await emailSvc.addMfaMethod(alice.id, {
          name: "email",
          confirmed: false,
          value: "unconfirmed@example.com",
        });
        const user = await emailSvc.getUser(alice.id);
        expect(await emailSvc.getCorrespondenceEmail(user)).toBeUndefined();
      });

      it("returns undefined when no source yields an address", async () => {
        const alice = await emailSvc.createUser("alice", "pass123");
        const user = await emailSvc.getUser(alice.id);
        expect(await emailSvc.getCorrespondenceEmail(user)).toBeUndefined();
      });

      it("never reads the column without emailField config — even when the row carries it", async () => {
        // `svc` (outer scope) has NO emailField; the column value must be invisible.
        const plainSvc = new UserService<Extras>(new UserStoreMemory<Extras>(), {
          password: { ...FAST_SCRYPT },
          clock: () => now,
        });
        const alice = await plainSvc.createUser("alice", "pass123", {
          contactEmail: "column@example.com",
        });
        await plainSvc.setVerifiedEmail(alice.id, "proved@example.com");
        const user = await plainSvc.getUser(alice.id);
        expect(await plainSvc.getCorrespondenceEmail(user)).toBe("proved@example.com");
      });
    });
  });
});
