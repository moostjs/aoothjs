import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Aooth } from "./aooth";
import { ppHasMinLength, ppHasUpperCase, ppNoRepeatedPasswords } from "./password-policies";
import { PasswordPolicy } from "./password-policy";
import { Password } from "./password";
import { UserCredentials } from "./user-credentials";
import { UsersStoreMemory } from "./users-store";

describe("aooth", () => {
  let store: UsersStoreMemory;
  let aooth: Aooth;

  beforeEach(() => {
    store = new UsersStoreMemory();
    aooth = new Aooth(store);
  });

  describe("constructor / config", () => {
    it("must apply default config", () => {
      const cfg = aooth.getConfig();
      expect(cfg.password.algorithm).toBe("sha3-224");
      expect(cfg.password.expiryDays).toBe(0);
      expect(cfg.password.historyLength).toBe(0);
      expect(cfg.password.pepper).toBe("");
      expect(cfg.password.resetTokenExpiryHours).toBe(1);
      expect(cfg.lockout.threshold).toBe(0);
      expect(cfg.lockout.duration).toBe(0);
      expect(cfg.mfa.required).toBe(false);
      expect(cfg.mfa.length).toBe(6);
    });

    it("must apply custom config", () => {
      const a = new Aooth(store, {
        password: {
          algorithm: "sha512",
          expiryDays: 90,
          historyLength: 5,
          pepper: "secret",
          resetTokenExpiryHours: 24,
          policies: [ppHasMinLength(10)],
        },
        lockout: { threshold: 5, duration: 60000 },
        mfa: { required: true, length: 8 },
      });
      const cfg = a.getConfig();
      expect(cfg.password.algorithm).toBe("sha512");
      expect(cfg.password.expiryDays).toBe(90);
      expect(cfg.password.historyLength).toBe(5);
      expect(cfg.password.pepper).toBe("secret");
      expect(cfg.password.resetTokenExpiryHours).toBe(24);
      expect(cfg.password.policies).toHaveLength(1);
      expect(cfg.lockout.threshold).toBe(5);
      expect(cfg.lockout.duration).toBe(60000);
      expect(cfg.mfa.required).toBe(true);
      expect(cfg.mfa.length).toBe(8);
    });

    it("must freeze config", () => {
      const cfg = aooth.getConfig();
      expect(Object.isFrozen(cfg)).toBe(true);
    });
  });

  describe("user() / password()", () => {
    it("must return UserCredentials instance", () => {
      const user = aooth.user("alice");
      expect(user).toBeInstanceOf(UserCredentials);
    });

    it("must return Password instance", () => {
      const pw = aooth.password();
      expect(pw).toBeInstanceOf(Password);
    });
  });

  describe("policies", () => {
    it("must return all policies", () => {
      const a = new Aooth(store, {
        password: { policies: [ppHasMinLength(8), ppHasUpperCase(1)] },
      });
      expect(a.getPasswordPolicies()).toHaveLength(2);
      expect(a.getPasswordPolicies()[0]).toBeInstanceOf(PasswordPolicy);
    });

    it("must return only transferable policies", () => {
      const a = new Aooth(store, {
        password: {
          policies: [ppHasMinLength(8), ppNoRepeatedPasswords(3)],
        },
      });
      const transferable = a.getTransferablePasswordPolicies();
      expect(transferable).toHaveLength(1);
      expect(transferable[0].rule).toBe("v.length >= 8");
      expect(transferable[0].description).toBe("Minimum length 8");
      expect(transferable[0].errorMessage).toBe("Password must be at least 8 characters long");
    });

    it("must return empty array when no policies", () => {
      expect(aooth.getPasswordPolicies()).toHaveLength(0);
      expect(aooth.getTransferablePasswordPolicies()).toHaveLength(0);
    });
  });

  describe("createUser", () => {
    it("must create user and return credentials", async () => {
      const user = await aooth.createUser("alice");
      expect(user).toBeInstanceOf(UserCredentials);
      const data = user.getData();
      expect(data.username).toBe("alice");
      expect(data.password.hash).toBeTruthy();
      expect(data.password.isInitial).toBe(true);
      expect(data.account.active).toBe(false);
    });

    it("must throw on duplicate username", async () => {
      await aooth.createUser("alice");
      await expect(aooth.createUser("alice")).rejects.toThrow(
        'User with id "alice" already exists',
      );
    });
  });

  describe("getUserData", () => {
    it("must return user data", async () => {
      await aooth.createUser("alice");
      const data = await aooth.getUserData("alice");
      expect(data.username).toBe("alice");
      expect(data.password).toBeDefined();
      expect(data.account).toBeDefined();
      expect(data.mfa).toBeDefined();
    });

    it("must throw for non-existent user", async () => {
      await expect(aooth.getUserData("nobody")).rejects.toThrow("Not found");
    });
  });

  describe("validatePassword", () => {
    let username: string;
    let generatedPassword: string;

    beforeEach(async () => {
      username = "bob";
      const user = await aooth.createUser(username);
      // set a known password
      const cfg = aooth.getConfig().password;
      user.changePassword(cfg, "Secret1!", "Secret1!");
      await user.save();
      generatedPassword = "Secret1!";
    });

    it("must return true for correct password", async () => {
      const result = await aooth.validatePassword(username, generatedPassword);
      expect(result).toBe(true);
    });

    it("must return false for wrong password", async () => {
      const result = await aooth.validatePassword(username, "wrong");
      expect(result).toBe(false);
    });

    it("must record loginSucceeded on correct password", async () => {
      await aooth.validatePassword(username, generatedPassword);
      const data = await aooth.getUserData(username);
      expect(data.account.lastLogin).toBeGreaterThan(0);
      expect(data.account.failedLoginAttempts).toBe(0);
    });

    it("must increment failedLoginAttempts on wrong password", async () => {
      await aooth.validatePassword(username, "wrong");
      const data = await aooth.getUserData(username);
      expect(data.account.failedLoginAttempts).toBe(1);
    });

    it("must not record effects when bypassEffect is true", async () => {
      await aooth.validatePassword(username, "wrong", true);
      const data = await aooth.getUserData(username);
      expect(data.account.failedLoginAttempts).toBe(0);
    });

    it("must lock account after threshold reached", async () => {
      const a = new Aooth(store, {
        lockout: { threshold: 3, duration: 60000 },
      });
      const user = await a.createUser("locktest");
      const cfg = a.getConfig().password;
      user.changePassword(cfg, "Correct1!", "Correct1!");
      await user.save();

      await a.validatePassword("locktest", "wrong1");
      await a.validatePassword("locktest", "wrong2");
      await a.validatePassword("locktest", "wrong3");

      const data = await a.getUserData("locktest");
      expect(data.account.locked).toBe(true);
      expect(data.account.lockReason).toBe("Too many login attempts");
      expect(data.account.lockEnds).toBeGreaterThan(0);
    });

    it("must lock permanently when duration is 0", async () => {
      const a = new Aooth(store, {
        lockout: { threshold: 2, duration: 0 },
      });
      const user = await a.createUser("permlock");
      const cfg = a.getConfig().password;
      user.changePassword(cfg, "Correct1!", "Correct1!");
      await user.save();

      await a.validatePassword("permlock", "wrong1");
      await a.validatePassword("permlock", "wrong2");

      const data = await a.getUserData("permlock");
      expect(data.account.locked).toBe(true);
      expect(data.account.lockEnds).toBe(0);
    });

    it("must reset failed attempts on successful login", async () => {
      await aooth.validatePassword(username, "wrong");
      await aooth.validatePassword(username, "wrong");
      let data = await aooth.getUserData(username);
      expect(data.account.failedLoginAttempts).toBe(2);

      await aooth.validatePassword(username, generatedPassword);
      data = await aooth.getUserData(username);
      expect(data.account.failedLoginAttempts).toBe(0);
    });
  });

  describe("isUserLocked", () => {
    it("must return locked status for locked user", async () => {
      const user = await aooth.createUser("locked-user");
      user.lockAccount("Manual lock", 0);
      await user.save();

      const status = await aooth.isUserLocked("locked-user");
      expect(status.locked).toBe(true);
      expect(status.reason).toBe("Manual lock");
    });

    it("must return unlocked status for normal user", async () => {
      await aooth.createUser("normal-user");
      const status = await aooth.isUserLocked("normal-user");
      expect(status.locked).toBe(false);
    });

    it("must auto-unlock when lock has expired and unlockWhenEnded is true", async () => {
      const user = await aooth.createUser("temp-locked");
      user.lockAccount("Temp lock", Date.now() - 1000); // expired 1s ago
      await user.save();

      const status = await aooth.isUserLocked("temp-locked", true);
      expect(status.locked).toBe(false);
    });
  });

  describe("genMfaCode", () => {
    it("must generate code of default length", () => {
      const code = aooth.genMfaCode();
      expect(code).toHaveLength(6);
      expect(code).toMatch(/^\d+$/);
    });

    it("must generate code of custom length", () => {
      const a = new Aooth(store, { mfa: { length: 8 } });
      const code = a.genMfaCode();
      expect(code).toHaveLength(8);
      expect(code).toMatch(/^\d+$/);
    });
  });
});
