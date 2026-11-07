import { AuthCredential, CredentialStoreJwt, CredentialStoreMemory } from "@aooth/auth";
import {
  EncapsulatedStateStrategy,
  hashWfHandle,
  HandleStateStrategy,
  type MoostWf,
  type WfState,
  type WfStateStrategy,
  WfStateStoreMemory,
} from "@moostjs/event-wf";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { deriveWfStateSecret, WfTriggerProvider } from "./provider";

// `stateRegistry()` never touches `wf` — a bare stub keeps the tests focused on
// the strategy registry without standing up a real MoostWf app.
const wfStub = {} as unknown as MoostWf;

// HS256 store carries a reusable symmetric secret, so `deriveStateKey` resolves
// — required for the default `wfStateSecret()` (encapsulated) path.
function jwtAuth(): AuthCredential {
  return new AuthCredential({
    store: new CredentialStoreJwt({ algorithm: "HS256", secret: "x".repeat(48) }),
  });
}

// Tiny subclass that only widens visibility of the protected seams under test.
class TestProvider extends WfTriggerProvider {
  publicStateRegistry() {
    return this.stateRegistry();
  }
  publicWfStateSecret() {
    return this.wfStateSecret();
  }
  publicTtl() {
    return this.wfStateEncapsulatedTtlMs();
  }
}

/** The strategy a registry entry wraps (aooth tags every registered strategy). */
const inner = (strategy: unknown): unknown => (strategy as { inner: unknown }).inner;

describe("WfTriggerProvider named strategy registry", () => {
  it("registry has `encapsulated`, `store` and `magic-link` keys with default = `encapsulated`", () => {
    // WHY: every wf starts cheap/serverless on the default; the swap targets
    // (`store`, and `magic-link` for link pauses) must exist in the registry
    // or `swapStrategy(...)` blows up.
    const p = new TestProvider(wfStub, jwtAuth());
    const reg = p.publicStateRegistry();
    expect(Object.keys(reg.strategies).toSorted()).toEqual(["encapsulated", "magic-link", "store"]);
    // The link strategy stores hashed handles, whatever the configured store.
    expect(inner(reg.strategies["magic-link"])).toBeInstanceOf(HandleStateStrategy);
    expect(reg.default).toBe("encapsulated");
  });

  it("both default entries are EncapsulatedStateStrategy instances", () => {
    // WHY: product decision — no real server-side store until a customer supplies
    // one. The bundled `store` entry must be encapsulated so a wf that swaps to
    // 'store' on the default config does not crash on a missing strategy.
    const p = new TestProvider(wfStub, jwtAuth());
    const reg = p.publicStateRegistry();
    expect(inner(reg.strategies.encapsulated)).toBeInstanceOf(EncapsulatedStateStrategy);
    expect(inner(reg.strategies.store)).toBeInstanceOf(EncapsulatedStateStrategy);
  });

  it("overriding storeStrategy() swaps ONLY the durable `store` entry", () => {
    // WHY: customers replace just the durable strategy (real Redis/DB store) and
    // keep the cheap encapsulated start path untouched.
    const durable = new HandleStateStrategy({ store: new WfStateStoreMemory() });
    class CustomerProvider extends TestProvider {
      protected override storeStrategy(): WfStateStrategy {
        return durable;
      }
    }
    const reg = new CustomerProvider(wfStub, jwtAuth()).publicStateRegistry();
    expect(inner(reg.strategies.store)).toBe(durable);
    expect(inner(reg.strategies.encapsulated)).toBeInstanceOf(EncapsulatedStateStrategy);
  });

  it("honors a dedicated wfStateSecret() override", () => {
    // WHY: the dedicated-secret seam — customers who don't want to reuse the auth
    // secret supply their own; the override must be the value the registry uses.
    // EncapsulatedStateStrategy decodes a string secret as hex → 64 hex chars = 32 bytes.
    const dedicated = "d".repeat(64);
    class DedicatedSecretProvider extends TestProvider {
      protected override wfStateSecret(): string | Buffer {
        return dedicated;
      }
    }
    // Built with a MEMORY-store AuthCredential whose deriveStateKey would THROW:
    // if the override is honored, no derive call happens and the registry builds.
    const p = new DedicatedSecretProvider(
      wfStub,
      new AuthCredential({ store: new CredentialStoreMemory() }),
    );
    expect(p.publicWfStateSecret()).toBe(dedicated);
    expect(() => p.publicStateRegistry()).not.toThrow();
    expect(inner(p.publicStateRegistry().strategies.encapsulated)).toBeInstanceOf(
      EncapsulatedStateStrategy,
    );
  });

  it("default wfStateSecret() goes through auth.deriveStateKey", () => {
    // WHY: the default secret REUSES the auth secret. Proven by construction with
    // a memory-store AuthCredential (no reusable symmetric secret): the default
    // path MUST call deriveStateKey, which throws — if the default ever stopped
    // routing through deriveStateKey, this would silently pass.
    const p = new TestProvider(wfStub, new AuthCredential({ store: new CredentialStoreMemory() }));
    expect(() => p.publicWfStateSecret()).toThrow();
    expect(() => p.publicStateRegistry()).toThrow();
  });

  it("wfStateEncapsulatedTtlMs() default is undefined", () => {
    // WHY: no TTL means an idle login form never expires server-side, so the
    // user can leave it open and still resume.
    const p = new TestProvider(wfStub, jwtAuth());
    expect(p.publicTtl()).toBeUndefined();
  });
});

describe("deriveWfStateSecret", () => {
  // WHY: a stateful store (atscript-db) has no secret to derive from, so the
  // default wfStateSecret() throws and the consumer must supply one. The
  // encapsulated strategy needs EXACTLY 32 bytes (a raw string is parsed as
  // hex), so this helper turns an arbitrary app secret into a usable key with
  // no node:crypto knowledge required. A regression here = lazy crash on the
  // first workflow start for every stateful-store consumer.
  it("produces exactly 32 bytes from an arbitrary-length secret", () => {
    expect(deriveWfStateSecret("short").length).toBe(32);
    expect(deriveWfStateSecret("a".repeat(1000)).length).toBe(32);
  });

  it("is deterministic (stable across restarts) and input-sensitive", () => {
    expect(deriveWfStateSecret("s3cr3t").equals(deriveWfStateSecret("s3cr3t"))).toBe(true);
    expect(deriveWfStateSecret("s3cr3t").equals(deriveWfStateSecret("other"))).toBe(false);
  });
});

describe("WfTriggerProvider.peek", () => {
  const state = {
    schemaId: "auth/invite/start",
    indexes: [3],
    context: { email: "a@x.test" },
  } as unknown as WfState;

  /** A provider whose durable `store` strategy stores hashed handles. */
  function hashedProvider() {
    const store = new WfStateStoreMemory();
    class Hashed extends TestProvider {
      protected override storeStrategy(): WfStateStrategy {
        return new HandleStateStrategy({ store, hashHandles: true });
      }
    }
    const p = new Hashed(wfStub, jwtAuth());
    const registry = p.publicStateRegistry();
    const persist = async (options?: { ttl?: number; expiresAt?: number }) =>
      `store.${await registry.strategies.store.persist(state, options)}`;
    return { p, registry, persist };
  }

  it("reads a valid token's state without consuming it", async () => {
    const { p, registry, persist } = hashedProvider();
    const token = await persist({ ttl: 60_000 });
    const before = Date.now();
    const peeked = await p.peek(token);
    expect(peeked?.schemaId).toBe("auth/invite/start");
    expect(peeked?.context).toEqual({ email: "a@x.test" });
    // The persist-time expiry rides along.
    const expiresAt = peeked?.meta?.aoothExpiresAt as number;
    expect(expiresAt).toBeGreaterThan(before);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 60_000);
    // Peeking again still finds it, and a resume can still consume it.
    expect(await p.peek(token)).not.toBeNull();
    expect(await registry.strategies.store.consume(token.slice("store.".length))).not.toBeNull();
    expect(await p.peek(token)).toBeNull();
  });

  it("an expired, unknown or malformed token is null", async () => {
    const { p, persist } = hashedProvider();
    const expired = await persist({ expiresAt: Date.now() - 1 });
    expect(await p.peek(expired)).toBeNull();
    for (const token of [
      "store.00000000-0000-4000-8000-000000000000",
      "",
      "store.",
      ".abc",
      "noprefix",
      "nope.abc",
      "constructor.abc",
    ]) {
      expect(await p.peek(token)).toBeNull();
    }
  });

  it("a hash-shaped token (a stored key, not a handle) is null", async () => {
    // WHY: with hashed handles the store holds `hash(handle)`; a value read
    // from the store must not open the state through the legacy raw-key path.
    const { p, persist } = hashedProvider();
    const token = await persist();
    const handle = token.slice("store.".length);
    expect(await p.peek(`store.${hashWfHandle(handle)}`)).toBeNull();
    expect(await p.peek(token)).not.toBeNull();
  });

  it("a state presented under another strategy's prefix is null", async () => {
    const { p, persist } = hashedProvider();
    const handle = (await persist()).slice("store.".length);
    expect(await p.peek(`magic-link.${handle}`)).toBeNull();
  });
});

describe("aoothExpiresAt records when the token stops working", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const state = { schemaId: "auth/invite/start", indexes: [1], context: {} } as unknown as WfState;
  const expiryOf = (peeked: WfState | null) => peeked?.meta?.aoothExpiresAt;
  const freezeNow = () => {
    vi.useFakeTimers({ toFake: ["Date"], now: 1_800_000_000_000 });
    return Date.now();
  };

  class EncapsulatedTtl extends TestProvider {
    ttl: number | undefined = undefined;
    protected override wfStateEncapsulatedTtlMs() {
      return this.ttl;
    }
  }

  it("with both ttl and expiresAt, the earlier one is recorded", async () => {
    const now = freezeNow();
    const strategy = new TestProvider(wfStub, jwtAuth()).publicStateRegistry().strategies
      .encapsulated;
    const sooner = await strategy.persist(state, { ttl: 60_000, expiresAt: now + 10_000 });
    expect(expiryOf(await strategy.retrieve(sooner))).toBe(now + 10_000);
    const later = await strategy.persist(state, { ttl: 5_000, expiresAt: now + 10_000 });
    expect(expiryOf(await strategy.retrieve(later))).toBe(now + 5_000);
    // The strategy agrees: the token dies at the recorded moment.
    vi.setSystemTime(now + 5_001);
    expect(await strategy.retrieve(later)).toBeNull();
    expect(await strategy.retrieve(sooner)).not.toBeNull();
    vi.setSystemTime(now + 10_001);
    expect(await strategy.retrieve(sooner)).toBeNull();
  });

  it("with neither, the strategy's default TTL is recorded (encapsulated and store)", async () => {
    const now = freezeNow();
    const p = new EncapsulatedTtl(wfStub, jwtAuth());
    p.ttl = 30_000;
    const { encapsulated } = p.publicStateRegistry().strategies;
    const token = await encapsulated.persist(state);
    expect(expiryOf(await encapsulated.retrieve(token))).toBe(now + 30_000);
    vi.setSystemTime(now + 30_001);
    expect(await encapsulated.retrieve(token)).toBeNull();

    vi.setSystemTime(now);
    class DurableTtl extends TestProvider {
      protected override storeStrategy(): WfStateStrategy {
        return new HandleStateStrategy({ store: new WfStateStoreMemory(), defaultTtl: 20_000 });
      }
    }
    const { store } = new DurableTtl(wfStub, jwtAuth()).publicStateRegistry().strategies;
    const handle = await store.persist(state);
    expect(expiryOf(await store.retrieve(handle))).toBe(now + 20_000);
    // An explicit ttl replaces the default; an absolute expiry alone ignores it.
    expect(expiryOf(await store.retrieve(await store.persist(state, { ttl: 5_000 })))).toBe(
      now + 5_000,
    );
    expect(
      expiryOf(await store.retrieve(await store.persist(state, { expiresAt: now + 90_000 }))),
    ).toBe(now + 90_000);
  });

  it("the recorded expiry is what the strategy reports through expiresAtFor", async () => {
    const now = freezeNow();
    const p = new EncapsulatedTtl(wfStub, jwtAuth());
    p.ttl = 30_000;
    const { encapsulated } = p.publicStateRegistry().strategies;
    const builtIn = (encapsulated as unknown as { inner: EncapsulatedStateStrategy }).inner;
    expect(builtIn.expiresAtFor?.()).toBe(now + 30_000);
    expect(expiryOf(await encapsulated.retrieve(await encapsulated.persist(state)))).toBe(
      builtIn.expiresAtFor?.(),
    );
  });

  it("no expiry is recorded when nothing bounds the state", async () => {
    const strategy = new TestProvider(wfStub, jwtAuth()).publicStateRegistry().strategies
      .encapsulated;
    const peeked = await strategy.retrieve(await strategy.persist(state));
    expect(peeked?.meta).not.toHaveProperty("aoothExpiresAt");
    // `0` (reported as "never") is not recorded either.
    const never = await strategy.retrieve(await strategy.persist(state, { ttl: 0 }));
    expect(never?.meta).not.toHaveProperty("aoothExpiresAt");
  });

  it("a custom strategy without expiresAtFor records nothing; one that has it is trusted", async () => {
    const memory = new Map<string, WfState>();
    const base: WfStateStrategy = {
      persist: async (s) => {
        const handle = `h${memory.size}`;
        memory.set(handle, s);
        return handle;
      },
      retrieve: async (handle) => memory.get(handle) ?? null,
      consume: async (handle) => memory.get(handle) ?? null,
    };
    class Custom extends TestProvider {
      strategy: WfStateStrategy = base;
      protected override storeStrategy(): WfStateStrategy {
        return this.strategy;
      }
    }
    const silent = new Custom(wfStub, jwtAuth());
    const { store } = silent.publicStateRegistry().strategies;
    // Neither the persist-time ttl nor expiresAt is recorded: the strategy did not report.
    const unknown = await store.retrieve(
      await store.persist(state, { ttl: 5_000, expiresAt: Date.now() + 9_000 }),
    );
    expect(unknown?.meta).not.toHaveProperty("aoothExpiresAt");

    const reporting = new Custom(wfStub, jwtAuth());
    reporting.strategy = { ...base, expiresAtFor: () => 1_900_000_000_000 };
    const reported = reporting.publicStateRegistry().strategies.store;
    expect(expiryOf(await reported.retrieve(await reported.persist(state)))).toBe(
      1_900_000_000_000,
    );
  });
});
