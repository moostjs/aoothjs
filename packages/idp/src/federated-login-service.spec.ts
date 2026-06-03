import { FederatedIdentityStoreMemory, UserService, UserStoreMemory } from "@aooth/user";
import { beforeEach, describe, expect, it } from "vitest";
import { FederatedLoginService } from "./federated-login-service";
import type { FederatedPolicy, NormalizedProfile } from "./types";

function profile(over: Partial<NormalizedProfile> = {}): NormalizedProfile {
  return { provider: "google", subject: "sub-1", raw: { sub: "sub-1" }, ...over };
}

let users: UserService;
let fed: FederatedIdentityStoreMemory;
let clockMs: number;

beforeEach(() => {
  clockMs = 1000;
  users = new UserService(new UserStoreMemory(), { clock: () => clockMs });
  fed = new FederatedIdentityStoreMemory({ clock: () => clockMs });
});

function svc(policy?: FederatedPolicy): FederatedLoginService {
  return new FederatedLoginService({ users, federated: fed, policy });
}

describe("resolveUser — new account (branch 3)", () => {
  it("creates + activates + links a fresh user", async () => {
    const out = await svc().resolveUser(profile({ email: "new@x.com", displayName: "New" }));
    if (out.kind !== "created") throw new Error(`expected created, got ${out.kind}`);
    expect(out.isNew).toBe(true);

    const user = await users.getUser(out.userId);
    expect(user.account.active).toBe(true); // federated signup IS the activation

    const row = await fed.find("google", "sub-1");
    expect(row?.userId).toBe(out.userId);
    expect(row?.email).toBe("new@x.com");
    expect(row?.displayName).toBe("New");
    expect(row?.lastLoginAt).toBe(1000);
  });

  it("does not promote the provider email to the account login handle", async () => {
    const out = await svc().resolveUser(profile({ email: "new@x.com" }));
    if (out.kind !== "created") throw new Error("expected created");
    const user = await users.getUser(out.userId);
    expect(user.email).toBeUndefined(); // email lives on the federated row only
  });

  it("denies signup when allowSignup is false", async () => {
    const out = await svc({ allowSignup: false }).resolveUser(profile());
    expect(out).toEqual({ kind: "denied", reason: "signup-disabled" });
    expect(await fed.find("google", "sub-1")).toBeNull();
  });

  it("falls back to provider:subject when the strategy username is taken", async () => {
    await users.createUser("taken"); // occupy the desired username
    const out = await svc({ usernameStrategy: () => "taken" }).resolveUser(profile());
    if (out.kind !== "created") throw new Error("expected created");
    const user = await users.getUser(out.userId);
    expect(user.username).toBe("google:sub-1");
  });
});

describe("resolveUser — known identity (branch 1)", () => {
  it("returns the linked user and refreshes the snapshot on each login", async () => {
    const first = await svc().resolveUser(profile({ displayName: "Old" }));
    if (first.kind !== "created") throw new Error("expected created");

    clockMs = 2000;
    const second = await svc().resolveUser(profile({ displayName: "New", subject: "sub-1" }));
    expect(second).toEqual({ kind: "linked", userId: first.userId, isNew: false });

    const row = await fed.find("google", "sub-1");
    expect(row?.displayName).toBe("New"); // snapshot refreshed
    expect(row?.lastLoginAt).toBe(2000); // lastLoginAt advanced
  });
});

describe("resolveUser — email match (branch 2)", () => {
  async function existingUserWithEmail(email: string): Promise<string> {
    const u = await users.createUser("alice", undefined, { email });
    return u.id;
  }

  it("require-interactive-link (default) surfaces the candidate, never silently merges", async () => {
    const candidateId = await existingUserWithEmail("shared@x.com");
    const out = await svc().resolveUser(profile({ email: "shared@x.com", emailVerified: true }));
    expect(out).toEqual({ kind: "needs-link", candidateUserId: candidateId });
    expect(await fed.find("google", "sub-1")).toBeNull(); // nothing linked yet
  });

  it("auto-links when verified + trusted under auto-link-if-verified", async () => {
    const candidateId = await existingUserWithEmail("shared@x.com");
    const out = await svc({
      emailMatch: "auto-link-if-verified",
      trustEmailVerifiedFrom: ["google"],
    }).resolveUser(profile({ email: "shared@x.com", emailVerified: true }));
    expect(out).toEqual({ kind: "auto-linked", userId: candidateId, isNew: false });
    expect((await fed.find("google", "sub-1"))?.userId).toBe(candidateId);
  });

  it("falls back to needs-link when the email is not verified", async () => {
    const candidateId = await existingUserWithEmail("shared@x.com");
    const out = await svc({
      emailMatch: "auto-link-if-verified",
      trustEmailVerifiedFrom: ["google"],
    }).resolveUser(profile({ email: "shared@x.com", emailVerified: false }));
    expect(out).toEqual({ kind: "needs-link", candidateUserId: candidateId });
  });

  it("falls back to needs-link when the provider is not trusted", async () => {
    const candidateId = await existingUserWithEmail("shared@x.com");
    const out = await svc({
      emailMatch: "auto-link-if-verified",
      trustEmailVerifiedFrom: [], // google NOT trusted
    }).resolveUser(profile({ email: "shared@x.com", emailVerified: true }));
    expect(out).toEqual({ kind: "needs-link", candidateUserId: candidateId });
  });

  it("create-separate ignores the email match and creates a new account", async () => {
    const candidateId = await existingUserWithEmail("shared@x.com");
    const out = await svc({ emailMatch: "create-separate" }).resolveUser(
      profile({ email: "shared@x.com", emailVerified: true }),
    );
    if (out.kind !== "created") throw new Error("expected created");
    expect(out.userId).not.toBe(candidateId);
  });
});

describe("linkIdentity — interactive link completion (§4)", () => {
  it("links a fresh identity to the authenticated user", async () => {
    const u = await users.createUser("bob");
    const row = await svc().linkIdentity({
      provider: "google",
      subject: "sub-9",
      userId: u.id,
      profile: { email: "bob@x.com" },
    });
    expect(row.userId).toBe(u.id);
    expect((await fed.find("google", "sub-9"))?.email).toBe("bob@x.com");
  });

  it("is idempotent when already linked to the same user", async () => {
    const u = await users.createUser("bob");
    const s = svc();
    await s.linkIdentity({ provider: "google", subject: "sub-9", userId: u.id });
    const again = await s.linkIdentity({ provider: "google", subject: "sub-9", userId: u.id });
    expect(again.userId).toBe(u.id);
  });

  it("rejects re-pointing an identity to a different user (confused-deputy guard)", async () => {
    const a = await users.createUser("a");
    const b = await users.createUser("b");
    const s = svc();
    await s.linkIdentity({ provider: "google", subject: "sub-9", userId: a.id });
    await expect(
      s.linkIdentity({ provider: "google", subject: "sub-9", userId: b.id }),
    ).rejects.toMatchObject({ name: "UserAuthError", type: "ALREADY_EXISTS" });
  });
});
