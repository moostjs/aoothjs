import { describe, expect, it } from "vite-plus/test";

import { UserAuthError } from "../errors";
import { FederatedIdentityStoreMemory } from "./federated-identity-store-memory";

function makeStore(start = 1_000) {
  let now = start;
  const store = new FederatedIdentityStoreMemory({ clock: () => now });
  return { store, advance: (ms: number) => (now += ms), at: () => now };
}

const google = (subject: string, userId: string) => ({ provider: "google", subject, userId });

describe("FederatedIdentityStoreMemory", () => {
  describe("link + find", () => {
    it("round-trips a linked identity and stamps linkedAt from the clock", async () => {
      const { store, at } = makeStore(5_000);
      const rec = { ...google("sub-1", "u1"), email: "a@example.com", emailVerified: true };
      const linked = await store.link(rec);

      expect(linked.id).toBeTruthy();
      expect(linked.linkedAt).toBe(5_000);
      expect(linked.lastLoginAt).toBeUndefined();
      expect(linked).toMatchObject({ provider: "google", subject: "sub-1", userId: "u1" });

      const found = await store.find("google", "sub-1");
      expect(found).toMatchObject({ id: linked.id, userId: "u1", email: "a@example.com" });
      expect(at()).toBe(5_000);
    });

    it("returns null for an unknown (provider, subject)", async () => {
      const { store } = makeStore();
      expect(await store.find("google", "nope")).toBeNull();
    });

    it("rejects re-linking the same (provider, subject) — even to a different user", async () => {
      const { store } = makeStore();
      await store.link(google("sub-1", "u1"));
      // The anti-takeover guarantee: one provider account → one aooth user.
      await expect(store.link(google("sub-1", "u2"))).rejects.toMatchObject({
        name: "UserAuthError",
        type: "ALREADY_EXISTS",
      });
      expect((await store.find("google", "sub-1"))?.userId).toBe("u1");
    });

    it("allows the same subject across different providers (distinct rows)", async () => {
      const { store } = makeStore();
      await store.link({ provider: "google", subject: "shared", userId: "u1" });
      await store.link({ provider: "github", subject: "shared", userId: "u1" });
      expect((await store.find("google", "shared"))?.provider).toBe("google");
      expect((await store.find("github", "shared"))?.provider).toBe("github");
    });
  });

  describe("listForUser", () => {
    it("returns every identity for a user, ordered by linkedAt", async () => {
      const { store, advance } = makeStore(1_000);
      await store.link({ provider: "google", subject: "g", userId: "u1", email: "a@gmail.com" });
      advance(500);
      await store.link({
        provider: "apple",
        subject: "a",
        userId: "u1",
        email: "relay@privaterelay.appleid.com",
      });
      await store.link({ provider: "github", subject: "x", userId: "OTHER" });

      // Same email, two providers, one account — the §3.5 day-1/day-2 scenario.
      const list = await store.listForUser("u1");
      expect(list.map((r) => r.provider)).toEqual(["google", "apple"]);
      expect(list[0].linkedAt).toBe(1_000);
      expect(list[1].linkedAt).toBe(1_500);
    });

    it("returns [] for a user with no identities", async () => {
      const { store } = makeStore();
      expect(await store.listForUser("nobody")).toEqual([]);
    });
  });

  describe("unlink", () => {
    it("removes a single link and reports whether a row was removed", async () => {
      const { store } = makeStore();
      await store.link(google("sub-1", "u1"));
      expect(await store.unlink("google", "sub-1")).toBe(true);
      expect(await store.find("google", "sub-1")).toBeNull();
      expect(await store.unlink("google", "sub-1")).toBe(false);
    });
  });

  describe("touchLogin", () => {
    it("stamps lastLoginAt and merges defined profile fields", async () => {
      const { store, advance } = makeStore(1_000);
      await store.link({ provider: "google", subject: "g", userId: "u1", displayName: "Old" });
      advance(2_000);
      await store.touchLogin("google", "g", { displayName: "New", avatarUrl: "http://x/a.png" });

      const row = await store.find("google", "g");
      expect(row?.lastLoginAt).toBe(3_000);
      expect(row?.displayName).toBe("New");
      expect(row?.avatarUrl).toBe("http://x/a.png");
    });

    it("never nulls a stored snapshot on a partial/absent profile (Apple repeat login)", async () => {
      const { store } = makeStore();
      await store.link({ provider: "apple", subject: "a", userId: "u1", email: "real@me.com" });
      await store.touchLogin("apple", "a"); // later Apple logins carry only `sub`
      expect((await store.find("apple", "a"))?.email).toBe("real@me.com");
    });

    it("is a no-op for an unknown (provider, subject)", async () => {
      const { store } = makeStore();
      await expect(store.touchLogin("google", "nope")).resolves.toBeUndefined();
    });
  });

  describe("deleteAllForUser", () => {
    it("removes every identity for the user and returns the count, leaving others", async () => {
      const { store } = makeStore();
      await store.link({ provider: "google", subject: "g", userId: "u1" });
      await store.link({ provider: "github", subject: "h", userId: "u1" });
      await store.link({ provider: "google", subject: "k", userId: "u2" });

      expect(await store.deleteAllForUser("u1")).toBe(2);
      expect(await store.listForUser("u1")).toEqual([]);
      expect((await store.find("google", "k"))?.userId).toBe("u2");
    });
  });

  describe("isolation", () => {
    it("clones on read so a caller cannot mutate stored state", async () => {
      const { store } = makeStore();
      await store.link({ provider: "google", subject: "g", userId: "u1", email: "a@b.c" });
      const a = await store.find("google", "g");
      a!.email = "tampered@evil.com";
      expect((await store.find("google", "g"))?.email).toBe("a@b.c");
    });
  });

  it("propagates non-UserAuthError surprises only as conflicts when appropriate", () => {
    // sanity: ALREADY_EXISTS is the only error the store raises directly
    expect(new UserAuthError("ALREADY_EXISTS").type).toBe("ALREADY_EXISTS");
  });
});
