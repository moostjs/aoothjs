import { describe, expect, it, beforeEach } from "vite-plus/test";
import { UserAuthError } from "./errors";
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
});
