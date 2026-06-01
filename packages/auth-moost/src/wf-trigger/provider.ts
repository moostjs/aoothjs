import { createHash } from "node:crypto";
import { AuthCredential } from "@aooth/auth";
import { createAsHttpOutlet, handleAsOutletRequest } from "@atscript/moost-wf";
import {
  EncapsulatedStateStrategy,
  MoostWf,
  type WfOutlet,
  type WfOutletTokenConfig,
  type WfOutletTriggerDeps,
  type WfStateStrategy,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { Injectable } from "moost";

/**
 * DI singleton owning the workflow-trigger wiring: state persistence, outlets,
 * and token wire. Consumers subclass to swap the durable state strategy, add
 * outlets (email, SMS, ...), or override `handle()` for per-request dispatch.
 *
 * State is a NAMED STRATEGY REGISTRY rather than a single strategy. Every
 * workflow STARTS on the `encapsulated` strategy (the registry default): state
 * rides inside the SPA-held token, so opening a login form persists ZERO
 * server-side rows before the first validated input — a restart/eviction can no
 * longer 410 GONE an idle form. A later step swaps to the durable `store`
 * strategy (`swapStrategy('store')`) once there is real state worth persisting.
 *
 * Per product decision BOTH registry entries default to `EncapsulatedStateStrategy`
 * — customers override only `storeStrategy()` to supply a real Redis/DB-backed
 * `HandleStateStrategy`, so `swapStrategy('store')` never crashes on the bundled
 * default. The encapsulated secret reuses the auth secret via
 * `AuthCredential.deriveStateKey("wf-state")` (HKDF-derived, stable across
 * restarts) unless `wfStateSecret()` is overridden with a dedicated secret.
 *
 * Outlets default to the HTTP outlet only; production deployments add the ones
 * they need by extending this class and re-binding via `setReplaceRegistry`.
 *
 * Uses `handleAsOutletRequest` (not `MoostWf.handleOutlet`) because the atscript
 * wrapper restores the `finished: true` marker that `<AsWfForm>` keys off — the
 * bare wooks request handler strips it during `useWfFinished()` unwrap.
 *
 * The trigger is a thin pass-through to `handleAsOutletRequest`: the new
 * `@atscript/moost-wf` wire envelope is `{ wfs, input: { action?, formData? } }`,
 * and the wf engine reads action + form data directly from `body.input`. No
 * app-level bridging of `body.action` is needed.
 */
/** Named state-strategy registry: the shape `handleAsOutletRequest` reads off `state`. */
type StateRegistry = { strategies: Record<string, WfStateStrategy>; default: string };

/**
 * Derive the exact 32-byte key the encapsulated wf-state strategy requires from
 * an arbitrary-length app secret.
 *
 * The default {@link WfTriggerProvider.wfStateSecret} reuses the auth secret via
 * `AuthCredential.deriveStateKey()`, which only works for stores backed by a
 * symmetric secret (JWT / encapsulated). A stateful store (e.g. atscript-db —
 * the recommended default once you adopt the session-listing APIs) has no key
 * material to derive from, so its `deriveStateKey()` throws. Such consumers must
 * override `wfStateSecret()` and supply their own secret — but the strategy
 * needs *exactly* 32 bytes (a raw string is otherwise parsed as hex), so the
 * obvious `return env.MY_SECRET` fails. This helper does the SHA-256-to-32-bytes
 * derivation for you, no `node:crypto` import required:
 *
 * ```ts
 * protected override wfStateSecret(): Buffer {
 *   return deriveWfStateSecret(env.MY_SECRET);
 * }
 * ```
 *
 * Deterministic — the same input always yields the same key, so it is stable
 * across restarts (matching what `deriveStateKey` provided).
 */
export function deriveWfStateSecret(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

@Injectable()
export class WfTriggerProvider {
  protected outlets: WfOutlet[] = [createAsHttpOutlet()];
  protected token: WfOutletTokenConfig = {
    read: ["body", "query", "cookie"],
    write: "body",
    name: "wfs",
  };

  constructor(
    protected readonly wf: MoostWf,
    protected readonly auth: AuthCredential,
  ) {}

  /**
   * Secret for the encapsulated wf-state token. Default reuses the auth secret
   * (HKDF-derived, stable across restarts) — which works only for stores backed
   * by a symmetric secret (JWT / encapsulated). A stateful store (atscript-db)
   * has nothing to derive from, so `deriveStateKey()` throws; those consumers
   * MUST override this and supply a dedicated secret. The strategy needs exactly
   * 32 bytes, so wrap your app secret in {@link deriveWfStateSecret}:
   * `return deriveWfStateSecret(env.MY_SECRET)`.
   */
  protected wfStateSecret(): string | Buffer {
    return this.auth.deriveStateKey("wf-state");
  }

  /** TTL (ms) for encapsulated pre-validation tokens. Default: undefined = no TTL (token valid until used), so an idle login form never expires server-side. */
  protected wfStateEncapsulatedTtlMs(): number | undefined {
    return undefined;
  }

  /** Durable strategy a workflow swaps to after the first validated input. Default = encapsulated (no real store); customers override to return e.g. new HandleStateStrategy({ store: <redis/db> }). */
  protected storeStrategy(): WfStateStrategy {
    return this.makeEncapsulated();
  }

  private makeEncapsulated(): WfStateStrategy {
    return new EncapsulatedStateStrategy({
      secret: this.wfStateSecret(),
      defaultTtl: this.wfStateEncapsulatedTtlMs(),
    });
  }

  private cachedState?: StateRegistry;

  /** Named strategy registry: every wf starts on `encapsulated` (default); a step calls swapStrategy('store') to move durable. Built lazily so subclass overrides (storeStrategy/wfStateSecret) are in effect. */
  protected stateRegistry(): StateRegistry {
    if (!this.cachedState) {
      this.cachedState = {
        strategies: { encapsulated: this.makeEncapsulated(), store: this.storeStrategy() },
        default: "encapsulated",
      };
    }
    return this.cachedState;
  }

  async handle(opts: { allow?: string[]; token?: WfOutletTokenConfig } = {}): Promise<unknown> {
    const wfApp = this.wf.getWfApp();
    const deps: WfOutletTriggerDeps = {
      // Forward `o.strategy` — the trigger resolves the registry default (start)
      // or the incoming token's prefix (resume) and passes it here; the wf
      // adapter sets the `wf.strategyName` slot from it, which the trigger then
      // reads back at pause time. Dropping it leaves the slot unset and the
      // trigger throws `Key "wf.strategyName" is not set` on every request.
      start: (schemaId, context, o) =>
        wfApp.start(schemaId, context as never, {
          input: o?.input,
          eventContext: (o?.eventContext ?? current()) as never,
          strategy: o?.strategy,
        }),
      resume: (state, o) =>
        wfApp.resume(state as { schemaId: string; indexes: number[]; context: never }, {
          input: o?.input,
          eventContext: (o?.eventContext ?? current()) as never,
          strategy: o?.strategy,
        }),
    };
    return handleAsOutletRequest(
      {
        ...(opts.allow && { allow: opts.allow }),
        state: this.stateRegistry(),
        outlets: this.outlets,
        token: opts.token ?? this.token,
      },
      deps,
    );
  }
}
