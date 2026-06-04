import { describe, expect, it } from "vite-plus/test";
import { DenylistStoreMemory } from "../stores/denylist-memory";
import { CredentialStoreEncapsulated } from "../stores/encapsulated";
import { CredentialStoreJwt } from "../stores/jwt";
import type { CredentialStore } from "../stores/store";
import type { Clock } from "../utils/clock";
import { AuthCredential } from "./auth-credential";

class FakeClock implements Clock {
  constructor(public time = 1_700_000_000_000) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

// Typed credential payload — flat root fields (replacing the dropped `claims`
// container). Optional, since a normal token carries none.
interface MyClaims {
  role?: "admin" | "user";
}

const JWT_SECRET = "integration-test-secret-of-sufficient-length-1234567890";
const ENC_SECRET = "encapsulated-integration-secret-1234567890";

type StoreFactory = (clock: Clock) => {
  store: CredentialStore<MyClaims>;
  denylist: DenylistStoreMemory;
};

const stateless: Array<[name: string, factory: StoreFactory]> = [
  [
    "JWT",
    (clock) => {
      const denylist = new DenylistStoreMemory({ clock });
      return {
        store: new CredentialStoreJwt<MyClaims>({ secret: JWT_SECRET, denylist, clock }),
        denylist,
      };
    },
  ],
  [
    "Encapsulated",
    (clock) => {
      const denylist = new DenylistStoreMemory({ clock });
      return {
        store: new CredentialStoreEncapsulated<MyClaims>({
          secret: ENC_SECRET,
          denylist,
          clock,
        }),
        denylist,
      };
    },
  ],
];

describe.each(stateless)("AuthCredential + %s store", (_, makeStore) => {
  it("issues, validates, and revokes via denylist", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({ store, clock, accessTtl: 60_000 });
    const { accessToken } = await auth.issue("alice", { role: "admin" });

    const ctx = await auth.validate(accessToken);
    expect(ctx?.userId).toBe("alice");
    expect(ctx?.role).toBe("admin");

    await auth.revoke(accessToken);
    expect(await auth.validate(accessToken)).toBeNull();
  });

  it("rejects a refresh token used as access (kind discriminant)", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({
      store,
      clock,
      refresh: { ttl: 600_000, rotation: "always" },
    });
    const issued = await auth.issue("alice");
    expect(issued.refreshToken).toBeTruthy();
    expect(await auth.validate(issued.refreshToken!)).toBeNull();
  });

  it("rejects an access token used as refresh", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({
      store,
      clock,
      refresh: { ttl: 600_000, rotation: "always" },
    });
    const issued = await auth.issue("alice");
    await expect(auth.refresh(issued.accessToken)).rejects.toMatchObject({
      type: "INVALID_TOKEN",
    });
  });

  it("rotation 'always': old refresh replay triggers theft response (cross-store)", async () => {
    // Stateless stores (JWT/Encapsulated) drop the consumed refresh behind a
    // denylist hit on retrieve, so reuse detection has to live in the
    // orchestrator's own consumed-refresh tracker rather than the store.
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({
      store,
      clock,
      accessTtl: 1000,
      refresh: { ttl: 600_000, rotation: "always" },
    });
    const initial = await auth.issue("alice");
    const refreshed = await auth.refresh(initial.refreshToken!);
    expect(refreshed.refreshToken).not.toBe(initial.refreshToken);

    await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
      type: "REFRESH_REUSE_DETECTED",
    });
  });

  it("rotation 'none': access reissue keeps refresh token usable", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({
      store,
      clock,
      accessTtl: 1000,
      refresh: { ttl: 600_000, rotation: "none" },
    });
    const initial = await auth.issue("alice");
    clock.advance(10);
    const a = await auth.refresh(initial.refreshToken!);
    expect(a.refreshToken).toBe(initial.refreshToken);
    clock.advance(10);
    const b = await auth.refresh(initial.refreshToken!);
    expect(b.refreshToken).toBe(initial.refreshToken);
    expect(a.accessToken).not.toBe(b.accessToken);
  });

  it("rotation 'sliding' degrades gracefully on stateless: first rotation succeeds, replay fails", async () => {
    // Documented behavior: stateless stores cannot mutate a token in place,
    // so the sliding grace window is unavailable; the second presentation of
    // the original refresh token is treated as unknown.
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({
      store,
      clock,
      accessTtl: 1000,
      refresh: { ttl: 600_000, rotation: "sliding", rotationGraceMs: 60_000 },
    });
    const initial = await auth.issue("alice");
    clock.advance(10);
    const first = await auth.refresh(initial.refreshToken!);
    expect(first.refreshToken).toBeTruthy();
    expect(first.refreshToken).not.toBe(initial.refreshToken);

    await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
      type: "INVALID_TOKEN",
    });

    // The fresh refresh token still works.
    const second = await auth.refresh(first.refreshToken!);
    expect(second.accessToken).toBeTruthy();
  });

  it("denylist hit returns null on validate (without store revoke)", async () => {
    const clock = new FakeClock();
    const { store, denylist } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({ store, clock, denylist });
    const { accessToken } = await auth.issue("alice");
    expect(await auth.validate(accessToken)).not.toBeNull();
    await denylist.add(accessToken, clock.now() + 60_000);
    expect(await auth.validate(accessToken)).toBeNull();
  });

  it("expired access token returns null on validate", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({ store, clock, accessTtl: 100 });
    const { accessToken } = await auth.issue("alice");
    clock.advance(200);
    expect(await auth.validate(accessToken)).toBeNull();
  });

  it("listForUser returns empty (stateless cannot enumerate)", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({ store, clock });
    await auth.issue("alice");
    await auth.issue("alice");
    expect(await auth.listForUser("alice")).toEqual([]);
  });

  it("revokeAllForUser is stateless-safe (no throw)", async () => {
    const clock = new FakeClock();
    const { store } = makeStore(clock);
    const auth = new AuthCredential<MyClaims>({ store, clock });
    await auth.issue("alice");
    // Stateless stores return 0 (no-op) or 1 (epoch bumped); per-store
    // behavior is asserted in the dedicated store specs.
    expect(typeof (await auth.revokeAllForUser("alice"))).toBe("number");
  });
});
