import { ppHasMinLength, UserAuthError, UserService, UserStoreMemory } from "@aoothjs/user";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import { AuthError } from "../errors";
import { CredentialStoreMemory } from "../stores/memory";
import type { Clock } from "../utils/clock";
import { PasswordReset } from "./password-reset";

// Low-cost scrypt for fast tests (mirrors user-service.spec.ts).
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };

class FakeClock implements Clock {
  constructor(public time: number) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

describe("PasswordReset", () => {
  let userStore: UserStoreMemory;
  let userService: UserService;
  let credStore: CredentialStoreMemory;
  let clock: FakeClock;
  let pr: PasswordReset;

  beforeEach(async () => {
    clock = new FakeClock(1_000_000);
    userStore = new UserStoreMemory();
    userService = new UserService(userStore, {
      password: { ...FAST_SCRYPT },
      clock: () => clock.now(),
    });
    credStore = new CredentialStoreMemory({ clock });
    pr = new PasswordReset({
      store: credStore,
      userService,
      clock,
    });
    await userService.createUser("alice", "OldPass1!");
  });

  describe("request", () => {
    it("returns a token + expiresAt for an existing user", async () => {
      const result = await pr.request("alice");
      expect(result).not.toBeNull();
      expect(typeof result!.resetToken).toBe("string");
      expect(result!.resetToken.length).toBeGreaterThan(0);
      expect(result!.expiresAt).toBe(clock.now() + 60 * 60 * 1000);
    });

    it("returns null for an unknown user", async () => {
      const result = await pr.request("bob");
      expect(result).toBeNull();
    });

    it("respects a custom TTL", async () => {
      const customPr = new PasswordReset({
        store: credStore,
        userService,
        ttl: 5_000,
        clock,
      });
      const result = await customPr.request("alice");
      expect(result!.expiresAt).toBe(clock.now() + 5_000);
    });

    it("uses 1 hour as the default TTL", async () => {
      const result = await pr.request("alice");
      expect(result!.expiresAt - clock.now()).toBe(60 * 60 * 1000);
    });
  });

  describe("execute", () => {
    it("applies the new password on a valid token", async () => {
      const { resetToken } = (await pr.request("alice"))!;
      await pr.execute(resetToken, "NewPass2!");
      expect(await userService.verifyPassword("alice", "NewPass2!")).toBe(true);
      expect(await userService.verifyPassword("alice", "OldPass1!")).toBe(false);
    });

    it("throws INVALID_TOKEN for an unknown token", async () => {
      try {
        await pr.execute("not-a-real-token", "NewPass2!");
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(AuthError);
        expect((e as AuthError).type).toBe("INVALID_TOKEN");
      }
    });

    it("consumes the token (second use throws INVALID_TOKEN)", async () => {
      const { resetToken } = (await pr.request("alice"))!;
      await pr.execute(resetToken, "NewPass2!");
      try {
        await pr.execute(resetToken, "AnotherPass3!");
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(AuthError);
        expect((e as AuthError).type).toBe("INVALID_TOKEN");
      }
    });

    it("throws INVALID_TOKEN for an expired token", async () => {
      const { resetToken } = (await pr.request("alice"))!;
      clock.advance(60 * 60 * 1000 + 1);
      try {
        await pr.execute(resetToken, "NewPass2!");
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(AuthError);
        expect((e as AuthError).type).toBe("INVALID_TOKEN");
      }
    });

    it("propagates UserAuthError on policy violation", async () => {
      const policyService = new UserService(userStore, {
        password: { ...FAST_SCRYPT, policies: [ppHasMinLength(8)] },
        clock: () => clock.now(),
      });
      const policyPr = new PasswordReset({
        store: credStore,
        userService: policyService,
        clock,
      });
      const { resetToken } = (await policyPr.request("alice"))!;
      try {
        await policyPr.execute(resetToken, "short");
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(UserAuthError);
        expect((e as UserAuthError).type).toBe("POLICY_VIOLATION");
      }
    });
  });
});
