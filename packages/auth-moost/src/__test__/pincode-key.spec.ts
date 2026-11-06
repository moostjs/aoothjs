import {
  AuthCredential,
  AuthError,
  CredentialStoreJwt,
  CredentialStoreMemory,
  RateLimitStoreMemory,
} from "@aooth/auth";
import type { UserService } from "@aooth/user";
import type { MoostWf } from "@moostjs/event-wf";
import { createEventContext, current } from "@wooksjs/event-core";
import { describe, expect, it } from "vite-plus/test";

import type { ConsentStore } from "../consent.store";
import { WfTriggerProvider } from "../wf-trigger/provider";
import { AuthWorkflow } from "../workflow/auth-workflow";
import { pincodeKeySlot } from "../workflow/pincode-key";
import { quietLogger } from "./flow-utils";

// WHY: one-time-code digests are keyed by what `WfTriggerProvider` publishes
// for its request, else by `AuthWorkflow`'s own fallback. Both must derive the
// same key, or a code minted on one path reads as a wrong code on the other.

type PinState = { pinNonce?: string; pinDigest?: string; pinExpire?: number };

class KeyWorkflow extends AuthWorkflow {
  mint(state: PinState): string {
    return this.mintPin(state, "subject|a@example.test");
  }
  verify(state: PinState, code: string): Promise<{ code: string } | null> {
    return this.verifyPin(state, code, "subject|a@example.test", "target");
  }
}

class KeyProvider extends WfTriggerProvider {
  publishedKey(): Buffer {
    return this.pincodeKey();
  }
  stateSecret(): string | Buffer {
    return this.wfStateSecret();
  }
}

/** A provider whose code secret is its own, not the default wf-state secret. */
class OwnSecretProvider extends KeyProvider {
  protected override pincodeSecret(): string {
    return "a-dedicated-code-secret";
  }
}

const wfStub = {} as unknown as MoostWf;

function jwtAuth(): AuthCredential {
  return new AuthCredential({
    store: new CredentialStoreJwt({ algorithm: "HS256", secret: "x".repeat(48) }),
  });
}

function workflow(auth: AuthCredential): KeyWorkflow {
  return new KeyWorkflow(
    { lockoutShadowStore: new RateLimitStoreMemory() },
    {} as UserService,
    auth,
    {} as ConsentStore,
  );
}

/** Run `fn` inside a request of `provider` (the key it publishes, as `handle()` does). */
function underProvider<T>(provider: KeyProvider, fn: () => T): T {
  return createEventContext({ logger: quietLogger }, () => {
    current().set(pincodeKeySlot, provider.publishedKey());
    return fn();
  });
}

describe("one-time-code key: one derivation inside and outside WfTriggerProvider", () => {
  it("a code minted under the provider verifies outside it", async () => {
    const auth = jwtAuth();
    const wf = workflow(auth);
    const state: PinState = {};
    const code = underProvider(new KeyProvider(wfStub, auth), () => wf.mint(state));
    expect(await wf.verify(state, code)).toBeNull();
  });

  it("a code minted outside the provider verifies under it", async () => {
    const auth = jwtAuth();
    const wf = workflow(auth);
    const state: PinState = {};
    const code = wf.mint(state);
    expect(
      await underProvider(new KeyProvider(wfStub, auth), () => wf.verify(state, code)),
    ).toBeNull();
  });

  it("the key is a subkey, never the wf-state (AES) secret itself", () => {
    const provider = new KeyProvider(wfStub, jwtAuth());
    expect(provider.publishedKey().equals(provider.stateSecret() as Buffer)).toBe(false);
  });

  it("a provider with its own code secret keys codes differently (the check discriminates)", async () => {
    const auth = jwtAuth();
    const wf = workflow(auth);
    const state: PinState = {};
    const code = underProvider(new OwnSecretProvider(wfStub, auth), () => wf.mint(state));
    expect(await wf.verify(state, code)).not.toBeNull();
  });

  it("outside a provider, a store without a derivable secret fails loudly (INVALID_CONFIG)", () => {
    const wf = workflow(new AuthCredential({ store: new CredentialStoreMemory() }));
    let thrown: unknown;
    try {
      wf.mint({});
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(AuthError);
    expect((thrown as AuthError).type).toBe("INVALID_CONFIG");
  });
});
