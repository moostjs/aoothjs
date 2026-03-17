import { describe, it, expect, beforeAll, beforeEach } from "vite-plus/test";
import { hashPassword } from "./crypto";
import type { TPasswordConfig, TAoothConfig } from "./types";
import { UserCredentials } from "./user-credentials";
import { UsersStoreMemory } from "./users-store/users-store-memory";

const persistentStore = new UsersStoreMemory();
let store: UsersStoreMemory;
let user: UserCredentials;
const config: TPasswordConfig &
  Pick<Required<Required<TAoothConfig>["password"]>, "saltGenerator"> = {
  saltGenerator: () => "salt",
  algorithm: "sha3-224",
};
const username = "test@user.com";

describe("user-credentials", () => {
  beforeAll(async () => {
    await new UserCredentials(persistentStore, "user1@test.com").create(config);
    await new UserCredentials(persistentStore, "user2@test.com").create(config);
    await new UserCredentials(persistentStore, "user3@test.com").create(config);
  });

  beforeEach(() => {
    store = new UsersStoreMemory();
    user = new UserCredentials(store, username);
  });
  it("must create user", async () => {
    await user.create(config);
    const data = user.getData();
    expect(data.username).toEqual(username);
    expect(data.account.active).toBe(false);
    expect(data.password.salt).toEqual("salt");
    expect(data.password.hash).toMatch(/^[A-Za-z0-9]+$/);
    expect(data.password.isInitial).toBe(true);
  });
  it("must change password", async () => {
    await user.create(config);
    user.changePassword(config, "newPassword", "newPassword");
    await user.save();
    const data = user.getData();
    expect(data.password.hash).toEqual(hashPassword("newPasswordsalt", config.algorithm));
    expect(data.password.history).toHaveLength(1);
  });
  it("must read user", async () => {
    const user = new UserCredentials(persistentStore, "user1@test.com");
    await user.read();
    const data = user.getData();
    expect(data.username).toEqual("user1@test.com");
    expect(data.account.active).toBe(false);
    expect(data.password.salt).toEqual("salt");
    expect(data.password.hash).toMatch(/^[A-Za-z0-9]+$/);
    expect(data.password.isInitial).toBe(true);
  });
  it("must activate user", async () => {
    const user = new UserCredentials(persistentStore, "user1@test.com");
    user.activateAccount();
    await user.save();
    const data = user.getData();
    expect(data.account.active).toBe(true);
    await user.read();
    expect(user.getData().account.active).toBe(true);
  });
  it("must (un)lock user", async () => {
    const user = new UserCredentials(persistentStore, "user1@test.com");
    user.lockAccount("test lock", 0);
    await user.save();
    const data = user.getData();
    expect(data.account.locked).toBe(true);
    await user.read();
    expect(user.getData().account.locked).toBe(true);
    user.unlockAccount();
    await user.save();
    expect(user.getData().account.locked).toBe(false);
    await user.read();
    expect(user.getData().account.locked).toBe(false);
  });
  it("must validate password", async () => {
    let user = new UserCredentials(persistentStore, "user1@test.com");
    await user.read();
    user.changePassword(config, "password", "password");
    await user.save();
    user = new UserCredentials(persistentStore, "user1@test.com");
    await user.read();
    expect(user.validatePassword(config, "password")).toBe(true);
  });
  it("must set lastLogin", async () => {
    const user = new UserCredentials(persistentStore, "user1@test.com");
    await user.read();
    expect(user.getData().account.lastLogin).toBe(0);
    user.loginSucceeded();
    await user.save();
    expect(user.getData().account.lastLogin).toBeGreaterThan(0);
  });
  it("must increase failed attempts", async () => {
    const user = new UserCredentials(persistentStore, "user1@test.com");
    await user.read();
    expect(user.getData().account.failedLoginAttempts).toBe(0);
    user.loginFailed();
    await user.save();
    expect(user.getData().account.failedLoginAttempts).toBe(1);
    user.loginFailed();
    await user.save();
    expect(user.getData().account.failedLoginAttempts).toBe(2);
  });
  it("must check users existence", async () => {
    expect(await new UserCredentials(persistentStore, "user1@test.com").exists()).toBeTruthy();
    expect(await new UserCredentials(persistentStore, "user2@test.com").exists()).toBeTruthy();
    expect(await new UserCredentials(persistentStore, "user3@test.com").exists()).toBeTruthy();
    expect(
      await new UserCredentials(persistentStore, "unknown-user@test.com").exists(),
    ).toBeFalsy();
  });

  it("must deactivate account", async () => {
    const user = new UserCredentials(persistentStore, "user1@test.com");
    await user.read();
    user.deactivateAccount();
    await user.save();
    expect(user.getData().account.active).toBe(false);
    await user.read(true);
    expect(user.getData().account.active).toBe(false);
  });

  it("must auto-detect email in username for MFA", async () => {
    await user.create(config);
    const data = user.getData();
    expect(data.mfa.email.address).toBe(username);
  });

  it("must not set email for non-email username", async () => {
    const nonEmailUser = new UserCredentials(store, "alice");
    await nonEmailUser.create(config);
    expect(nonEmailUser.getData().mfa.email.address).toBe("");
  });

  it("must mask email address", async () => {
    await user.create(config);
    user.getData().mfa.email.address = "longname@example.com";
    const masked = user.getEmailMasked();
    expect(masked).toContain("***");
    expect(masked).toContain("@example.com");
    expect(masked).not.toBe("longname@example.com");
  });

  it("must return empty string when no email", async () => {
    const u = new UserCredentials(store, "nomail");
    await u.create(config);
    expect(u.getEmailMasked()).toBe("");
  });

  it("must mask phone number", async () => {
    await user.create(config);
    user.getData().mfa.sms.number = "+1234567890";
    const masked = user.getPhoneMasked();
    expect(masked).toContain("***");
    expect(masked).not.toBe("+1234567890");
  });

  it("must return empty string when no phone", async () => {
    await user.create(config);
    expect(user.getPhoneMasked()).toBe("");
  });

  it("must mask short strings as ***", async () => {
    await user.create(config);
    user.getData().mfa.email.address = "ab@x.co";
    const masked = user.getEmailMasked();
    expect(masked).toContain("***");
  });

  describe("MFA options", () => {
    it("must return empty array when no MFA confirmed", async () => {
      await user.create(config);
      expect(user.getMfaOptions()).toHaveLength(0);
    });

    it("must include confirmed email", async () => {
      await user.create(config);
      user.getData().mfa.email.confirmed = true;
      user.getData().mfa.email.address = "test@user.com";
      const opts = user.getMfaOptions();
      expect(opts).toHaveLength(1);
      expect(opts[0].type).toBe("email");
      expect(opts[0].value).toBe("test@user.com");
      expect(opts[0].isDefault).toBe(false);
    });

    it("must include confirmed sms", async () => {
      await user.create(config);
      user.getData().mfa.sms.confirmed = true;
      user.getData().mfa.sms.number = "+1234567890";
      const opts = user.getMfaOptions();
      expect(opts).toHaveLength(1);
      expect(opts[0].type).toBe("sms");
    });

    it("must include totp when secretKey is set", async () => {
      await user.create(config);
      user.getData().mfa.totp.secretKey = "JBSWY3DPEHPK3PXP";
      const opts = user.getMfaOptions();
      expect(opts).toHaveLength(1);
      expect(opts[0].type).toBe("totp");
      expect(opts[0].masked).toBe("");
    });

    it("must mark default method", async () => {
      await user.create(config);
      user.getData().mfa.email.confirmed = true;
      user.getData().mfa.email.address = "test@user.com";
      user.getData().mfa.default = "email";
      const opts = user.getMfaOptions();
      expect(opts[0].isDefault).toBe(true);
    });
  });

  it("must set MFA default method and reset autoSend", async () => {
    await user.create(config);
    user.setMfaDefaultMethod("email");
    await user.save();
    expect(user.getData().mfa.default).toBe("email");
    expect(user.getData().mfa.autoSend).toBe(false);
  });

  it("must set MFA autoSend", async () => {
    await user.create(config);
    user.setMfaAutoSend(true);
    await user.save();
    expect(user.getData().mfa.autoSend).toBe(true);
  });

  it("must set MFA confirmed for email", async () => {
    await user.create(config);
    user.setMfaConfirmed("email");
    await user.save();
    expect(user.getData().mfa.email.confirmed).toBe(true);
  });

  it("must set MFA confirmed for sms", async () => {
    await user.create(config);
    user.setMfaConfirmed("sms", true);
    await user.save();
    expect(user.getData().mfa.sms.confirmed).toBe(true);
  });

  describe("isLocked", () => {
    it("must return unlocked for normal user", async () => {
      await user.create(config);
      const status = user.isLocked();
      expect(status.locked).toBe(false);
      expect(status.reason).toBe("");
      expect(status.endsIn).toBe("");
    });

    it("must return locked with permanent lock", async () => {
      await user.create(config);
      user.lockAccount("perm", 0);
      await user.save();
      const status = user.isLocked();
      expect(status.locked).toBe(true);
      expect(status.reason).toBe("perm");
      expect(status.ends).toBe(0);
      expect(status.endsIn).toBe("");
    });

    it("must return locked with timed lock", async () => {
      await user.create(config);
      const futureTime = Date.now() + 300000; // 5 minutes
      user.lockAccount("timed", futureTime);
      await user.save();
      const status = user.isLocked();
      expect(status.locked).toBe(true);
      expect(status.endsIn).toContain("more minute(s)");
    });

    it("must auto-unlock expired lock when unlockWhenEnded is true", async () => {
      await user.create(config);
      user.lockAccount("expired", Date.now() - 1000);
      await user.save();
      const status = user.isLocked(true);
      expect(status.locked).toBe(false);
      expect(status.reason).toBe("");
    });

    it("must not auto-unlock when unlockWhenEnded is false", async () => {
      await user.create(config);
      user.lockAccount("expired", Date.now() - 1000);
      await user.save();
      const status = user.isLocked(false);
      expect(status.locked).toBe(true);
    });

    it("must not auto-unlock permanent lock even with unlockWhenEnded", async () => {
      await user.create(config);
      user.lockAccount("perm", 0);
      await user.save();
      const status = user.isLocked(true);
      expect(status.locked).toBe(true);
    });
  });

  describe("read caching", () => {
    it("must cache result on second read", async () => {
      const u = new UserCredentials(persistentStore, "user2@test.com");
      const d1 = await u.read();
      const d2 = await u.read();
      expect(d1).toBe(d2); // same reference
    });

    it("must re-read from store with force=true", async () => {
      const u = new UserCredentials(persistentStore, "user2@test.com");
      const d1 = await u.read();
      const d2 = await u.read(true);
      expect(d1).not.toBe(d2); // different reference (structuredClone)
    });
  });

  it("must throw when reading non-existent user", async () => {
    const u = new UserCredentials(store, "ghost");
    await expect(u.read()).rejects.toThrow("Not found");
  });

  it("must throw on mismatched passwords", async () => {
    await user.create(config);
    expect(() => user.changePassword(config, "abc", "xyz")).toThrow("Passwords don't match");
  });
});
