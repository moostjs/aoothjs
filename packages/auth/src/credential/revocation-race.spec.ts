import { describe, expect, it } from "vite-plus/test";

import { CredentialStoreAtscriptDb } from "../atscript-db";
import { MockTable } from "../atscript-db/__test__/mock-table";
import { CredentialStoreRedis } from "../redis";
import { MockRedis } from "../redis/__test__/mock-redis";
import { CredentialStoreMemory } from "../stores/memory";
import type { CredentialStore } from "../stores/store";
import { AuthCredential } from "./auth-credential";

// A refresh in flight while a session is being revoked must not leave live
// credentials in the revoked session behind. Two interleavings per revoke path:
//
// - "mint after revoke": the refresh read the old refresh row, then the whole
//   revocation ran, then the refresh minted its new pair.
// - "revoke lists, refresh completes, revoke deletes": the revocation listed
//   the session's rows before the refresh minted, and deleted them after.

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
}

function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * Wrap `target` so calls of a named method wait at a gate until it is released
 * — a deterministic pause point inside the store (or Redis client) under test.
 */
function gated<T extends object>(target: T) {
  const hooks = new Map<PropertyKey, () => Promise<void>>();
  const proxy = new Proxy(target, {
    get(t, prop, receiver) {
      const value = Reflect.get(t, prop, receiver) as unknown;
      const hook = hooks.get(prop);
      if (typeof value !== "function" || !hook) return value;
      return async (...args: unknown[]) => {
        await hook();
        return (value as (...a: unknown[]) => unknown).apply(receiver, args);
      };
    },
  });
  /** Hold every `method` call from now until the returned `release()` is called. */
  const pauseNext = (method: string) => {
    const reached = deferred();
    const gate = deferred();
    hooks.set(method, async () => {
      reached.resolve();
      await gate.promise;
    });
    const release = () => {
      hooks.delete(method);
      gate.resolve();
    };
    return { reached: reached.promise, release };
  };
  return { proxy, pauseNext };
}

interface StoreUnderTest {
  store: CredentialStore;
  /** Pause point between the revocation's listing and its deletes, if the store has one. */
  pauseRevokeAllDelete?: () => { reached: Promise<void>; release: () => void };
}

const stores: Array<[string, () => StoreUnderTest]> = [
  ["memory", () => ({ store: new CredentialStoreMemory() })],
  [
    "redis",
    () => {
      const redis = gated(new MockRedis());
      return {
        store: new CredentialStoreRedis({ redis: redis.proxy }),
        pauseRevokeAllDelete: () => redis.pauseNext("del"),
      };
    },
  ],
  ["atscript-db", () => ({ store: new CredentialStoreAtscriptDb({ table: new MockTable() }) })],
];

type RevokePath = "revokeSession" | "revokeOtherSessions" | "revokeAllForUser";
const paths: RevokePath[] = ["revokeSession", "revokeOtherSessions", "revokeAllForUser"];

async function setup(make: () => StoreUnderTest) {
  const sut = make();
  const store = gated(sut.store);
  const auth = new AuthCredential({
    store: store.proxy,
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "sliding" },
  });
  const victim = await auth.issue("alice");
  const victimSession = (await auth.validate(victim.accessToken))!.sessionId!;
  const keeper = await auth.issue("alice");
  const keeperSession = (await auth.validate(keeper.accessToken))!.sessionId!;
  const revoke = (path: RevokePath) =>
    path === "revokeSession"
      ? auth.revokeSession("alice", victimSession)
      : path === "revokeOtherSessions"
        ? auth.revokeOtherSessions("alice", keeperSession)
        : auth.revokeAllForUser("alice");
  return { sut, store, auth, victim, victimSession, revoke };
}

/** Nothing of the revoked session may survive: no rows, no usable token. */
async function expectSessionGone(
  auth: AuthCredential,
  sessionId: string,
  minted: { accessToken: string; refreshToken?: string } | Error,
): Promise<void> {
  const rows = (await auth.listSessions("alice", { kind: "*" })) as Array<{ sessionId: string }>;
  expect(rows.map((r) => r.sessionId)).not.toContain(sessionId);
  if (minted instanceof Error) return;
  expect(await auth.validate(minted.accessToken)).toBeNull();
  await expect(auth.refresh(minted.refreshToken!)).rejects.toThrow();
}

describe.each(stores)("refresh racing a revocation — %s store", (_name, make) => {
  it.each(paths)(
    "%s: a refresh that mints after the revocation leaves nothing alive",
    async (path) => {
      const { store, auth, victim, victimSession, revoke } = await setup(make);
      // Pause the refresh right before it persists its new access row.
      const pause = store.pauseNext("persist");
      const inflight = auth.refresh(victim.refreshToken!).catch((err: Error) => err);
      await pause.reached;
      await revoke(path);
      pause.release();
      const minted = await inflight;
      expect(minted).toBeInstanceOf(Error);
      await expectSessionGone(auth, victimSession, minted);
    },
  );

  it.each(paths.filter((p) => p !== "revokeAllForUser"))(
    "%s: a refresh minting between the revocation's listing and its deletes leaves nothing alive",
    async (path) => {
      const { store, auth, victim, victimSession, revoke } = await setup(make);
      // Pause the revocation at its first delete (after it listed the rows),
      // let the refresh run to completion, then let the revocation finish.
      const pause = store.pauseNext("revoke");
      const revoking = revoke(path);
      await pause.reached;
      const minted = await auth.refresh(victim.refreshToken!);
      pause.release();
      await revoking;
      await expectSessionGone(auth, victimSession, minted);
    },
  );
});

describe("refresh racing revokeAllForUser between its listing and its deletes — redis store", () => {
  it("leaves nothing alive", async () => {
    const { sut, auth, victim, victimSession, revoke } = await setup(stores[1][1]);
    const pause = sut.pauseRevokeAllDelete!();
    const revoking = revoke("revokeAllForUser");
    await pause.reached;
    const minted = await auth.refresh(victim.refreshToken!);
    pause.release();
    await revoking;
    await expectSessionGone(auth, victimSession, minted);
  });
});

/**
 * Hold the N-th call of `method` right AFTER it returned (its snapshot is
 * taken, the caller's deletes not yet issued), for each requested N.
 */
function holdAfter<T extends object>(target: T, method: string) {
  let calls = 0;
  const holds = new Map<number, { reached: () => void; open: Promise<void> }>();
  const proxy = new Proxy(target, {
    get(t, prop, receiver) {
      const value = Reflect.get(t, prop, receiver) as unknown;
      if (prop !== method || typeof value !== "function") return value;
      return async (...args: unknown[]) => {
        const n = ++calls;
        const out = await (value as (...a: unknown[]) => Promise<unknown>).apply(receiver, args);
        const hold = holds.get(n);
        if (hold) {
          hold.reached();
          await hold.open;
        }
        return out;
      };
    },
  });
  const at = (n: number) => {
    const reached = deferred();
    const open = deferred();
    holds.set(n, { reached: reached.resolve, open: open.promise });
    return { reached: reached.promise, release: open.resolve };
  };
  return { proxy, at };
}

// A CHAIN of refreshes — each minting off the previous one's fresh refresh
// token, each right after the revocation took a listing — must not outrun it.
describe.each(stores)("a chain of refreshes racing a revocation — %s store", (_name, make) => {
  it.each(paths.filter((p) => p !== "revokeAllForUser"))("%s", async (path) => {
    const listing = holdAfter(make().store, "listForUser");
    const auth = new AuthCredential({
      store: listing.proxy,
      accessTtl: 60_000,
      refresh: { ttl: 600_000, rotation: "sliding" },
    });
    const victim = await auth.issue("alice");
    const victimSession = (await auth.validate(victim.accessToken))!.sessionId!;
    const keeper = await auth.issue("alice");
    const keeperSession = (await auth.validate(keeper.accessToken))!.sessionId!;
    // Listings #1/#2 below are the revocation's own (setup made none).
    const first = listing.at(1);
    const second = listing.at(2);
    const revoking =
      path === "revokeSession"
        ? auth.revokeSession("alice", victimSession)
        : auth.revokeOtherSessions("alice", keeperSession);
    await first.reached;
    const r1 = await auth.refresh(victim.refreshToken!);
    first.release();
    await second.reached;
    const r2 = await auth.refresh(r1.refreshToken!);
    second.release();
    await revoking;
    await expectSessionGone(auth, victimSession, r2);
  });
});

describe("a chain of refreshes racing revokeAllForUser — redis store", () => {
  it("leaves nothing alive", async () => {
    const redis = holdAfter(new MockRedis(), "smembers");
    const auth = new AuthCredential({
      store: new CredentialStoreRedis({ redis: redis.proxy }),
      accessTtl: 60_000,
      refresh: { ttl: 600_000, rotation: "sliding" },
    });
    const victim = await auth.issue("alice");
    const victimSession = (await auth.validate(victim.accessToken))!.sessionId!;
    const first = redis.at(1);
    const second = redis.at(2);
    const revoking = auth.revokeAllForUser("alice");
    await first.reached;
    const r1 = await auth.refresh(victim.refreshToken!);
    first.release();
    await second.reached;
    const r2 = await auth.refresh(r1.refreshToken!);
    second.release();
    await revoking;
    await expectSessionGone(auth, victimSession, r2);
  });
});

describe("a revocation that never converges", () => {
  it("fails loudly instead of spinning against a refresh loop", async () => {
    const listing = holdAfter(new CredentialStoreMemory(), "listForUser");
    const auth = new AuthCredential({
      store: listing.proxy,
      accessTtl: 60_000,
      refresh: { ttl: 600_000, rotation: "sliding" },
    });
    const victim = await auth.issue("alice");
    const sessionId = (await auth.validate(victim.accessToken))!.sessionId!;
    const holds = Array.from({ length: 20 }, (_, i) => listing.at(i + 1));
    const revoking = auth.revokeSession("alice", sessionId).then(
      () => "converged",
      (err: Error) => err.message,
    );
    // After every listing, mint once more off the newest refresh token.
    let latest = victim.refreshToken!;
    for (const hold of holds) {
      const next = await Promise.race([hold.reached.then(() => "listed"), revoking]);
      if (next !== "listed") break;
      latest = (await auth.refresh(latest)).refreshToken!;
      hold.release();
    }
    expect(await revoking).toMatch(/did not converge/);
  });
});
