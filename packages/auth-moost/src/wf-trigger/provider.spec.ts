import { AuthCredential, CredentialStoreJwt, CredentialStoreMemory } from "@aooth/auth";
import {
  EncapsulatedStateStrategy,
  HandleStateStrategy,
  type MoostWf,
  type WfStateStrategy,
  WfStateStoreMemory,
} from "@moostjs/event-wf";
import { describe, expect, it } from "vite-plus/test";

import { WfTriggerProvider } from "./provider";

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

describe("WfTriggerProvider named strategy registry", () => {
  it("registry has both `encapsulated` and `store` keys with default = `encapsulated`", () => {
    // WHY: every wf starts cheap/serverless on the default; the swap target
    // (`store`) must exist in the registry or `swapStrategy('store')` blows up.
    const p = new TestProvider(wfStub, jwtAuth());
    const reg = p.publicStateRegistry();
    expect(Object.keys(reg.strategies).toSorted()).toEqual(["encapsulated", "store"]);
    expect(reg.default).toBe("encapsulated");
  });

  it("both default entries are EncapsulatedStateStrategy instances", () => {
    // WHY: product decision — no real server-side store until a customer supplies
    // one. The bundled `store` entry must be encapsulated so a wf that swaps to
    // 'store' on the default config does not crash on a missing strategy.
    const p = new TestProvider(wfStub, jwtAuth());
    const reg = p.publicStateRegistry();
    expect(reg.strategies.encapsulated).toBeInstanceOf(EncapsulatedStateStrategy);
    expect(reg.strategies.store).toBeInstanceOf(EncapsulatedStateStrategy);
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
    expect(reg.strategies.store).toBe(durable);
    expect(reg.strategies.encapsulated).toBeInstanceOf(EncapsulatedStateStrategy);
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
    expect(p.publicStateRegistry().strategies.encapsulated).toBeInstanceOf(
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
