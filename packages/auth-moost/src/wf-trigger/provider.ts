import { createHash } from "node:crypto";
import { AuthCredential } from "@aooth/auth";
import { createAsHttpOutlet, handleAsOutletRequest } from "@atscript/moost-wf";
import {
  EncapsulatedStateStrategy,
  HandleStateStrategy,
  MoostWf,
  normalizeWfId,
  type WfOutlet,
  type WfOutletTokenConfig,
  type WfOutletTriggerConfig,
  type WfOutletTriggerDeps,
  type WfPauseRequest,
  type WfPersistOptions,
  type WfState,
  type WfStateStore,
  WfStateStoreMemory,
  type WfStateStrategy,
  type WfTriggerErrorBody,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { Injectable } from "moost";

import { createInviteOutlet, reservePendingInviteLink } from "../workflow/invite-outlet";
import { createMagicLinkOutlet, MAGIC_LINK_STRATEGY } from "../workflow/magic-link-outlet";
import { derivePincodeKey, pincodeKeySlot, WF_STATE_KEY_LABEL } from "../workflow/pincode-key";
import { withoutPublicProjection } from "../workflow/public-projection";
import { aoothHttpError } from "../http-messages";

/** Cap of the default (in-memory) magic-link store. */
export const MAGIC_LINK_STORE_MAX_ENTRIES = 10_000;

/**
 * The default magic-link store: memory, with expired links swept at most once
 * a minute on write, and at most {@link MAGIC_LINK_STORE_MAX_ENTRIES} links —
 * the oldest is dropped first. Links nobody clicks (and requests for unknown
 * identifiers) must not pile up for the life of the process.
 */
export class BoundedWfStateStoreMemory extends WfStateStoreMemory {
  private lastSweep = 0;
  /** The stored handles, oldest first, with their expiry (the base map is private). */
  private readonly expiries = new Map<string, number | undefined>();
  constructor(private readonly maxEntries = MAGIC_LINK_STORE_MAX_ENTRIES) {
    super();
  }
  override async set(handle: string, state: WfState, expiresAt?: number): Promise<void> {
    const now = Date.now();
    if (now - this.lastSweep > 60_000) {
      this.lastSweep = now;
      await this.cleanup();
      for (const [key, expiry] of this.expiries) {
        if (expiry && now > expiry) this.expiries.delete(key);
      }
    }
    this.expiries.delete(handle);
    while (this.expiries.size >= this.maxEntries) {
      const oldest = this.expiries.keys().next().value as string;
      this.expiries.delete(oldest);
      await super.delete(oldest);
    }
    this.expiries.set(handle, expiresAt);
    return super.set(handle, state, expiresAt);
  }
  override async delete(handle: string): Promise<void> {
    this.expiries.delete(handle);
    return super.delete(handle);
  }
  override async getAndDelete(handle: string): ReturnType<WfStateStoreMemory["getAndDelete"]> {
    this.expiries.delete(handle);
    return super.getAndDelete(handle);
  }
}

/** Where aooth records, inside a persisted state, which strategy persisted it. */
const STRATEGY_TAG = "aoothStrategy";
/**
 * Where aooth records, inside a persisted state, when it expires (ms; absent =
 * never, or unknown for a custom strategy).
 */
export const STATE_EXPIRES_KEY = "aoothExpiresAt";
/** Padding aooth adds to encapsulated states (stripped on read). */
const PAD_KEY = "aoothPad";
/** Encapsulated payloads are padded to a multiple of this many bytes. */
const PAD_BUCKET = 256;
/** Strategies new enough that every state they hold carries the tag. */
const TAG_REQUIRED = new Set([MAGIC_LINK_STRATEGY]);

type WfStateMeta = Record<string, unknown>;

/**
 * Wrap a registered strategy so a state can only be resumed through the
 * strategy that persisted it: `persist` tags the state with `name`, and
 * `retrieve` / `consume` refuse (as "not found") a state tagged by another
 * strategy — e.g. a magic-link entry presented as a `store.` token when both
 * share one store. A refused state is checked before it is consumed, so the
 * attempt does not destroy it. States persisted before tagging existed are
 * accepted, except by strategies that always tag. Encapsulated states are also
 * padded to a {@link PAD_BUCKET}-byte multiple, so the token's length does not
 * follow the length of what is inside. The expiry the strategy applies is
 * recorded too ({@link STATE_EXPIRES_KEY}), as the strategy reports it through
 * `expiresAtFor` (the earlier of the persist-time `ttl` / `expiresAt`, else its
 * own default TTL), so a peek can tell when the token stops working. A strategy
 * without `expiresAtFor` (a custom one, or a built-in with `persist` overridden)
 * leaves it unrecorded.
 */
function tagStrategy(name: string, strategy: WfStateStrategy): WfStateStrategy {
  const pad = strategy instanceof EncapsulatedStateStrategy;
  const accepts = (state: WfState | null): state is WfState => {
    if (!state) return false;
    const tag = state.meta?.[STRATEGY_TAG];
    return tag === undefined ? !TAG_REQUIRED.has(name) : tag === name;
  };
  const tagged = (state: WfState, options?: WfPersistOptions): WfState => {
    const {
      [PAD_KEY]: _pad,
      [STATE_EXPIRES_KEY]: _expires,
      ...meta
    } = (state.meta ?? {}) as WfStateMeta;
    // The expiry the strategy will apply: positive = record it; `0` = never
    // expires and `undefined` = unknown (no `expiresAtFor`) = record nothing.
    const reported = strategy.expiresAtFor?.(options);
    const expiresAt = reported !== undefined && reported > 0 ? reported : undefined;
    const out = {
      ...state,
      meta: {
        ...meta,
        [STRATEGY_TAG]: name,
        ...(expiresAt !== undefined && { [STATE_EXPIRES_KEY]: expiresAt }),
      },
    } as WfState;
    if (!pad) return out;
    // `{"s":<state>,"e":<expiry>}` is what the strategy encrypts; the expiry's
    // length is the same for every state of one configuration.
    const size = Buffer.byteLength(JSON.stringify(out)) + 32;
    const fill = (PAD_BUCKET - (size % PAD_BUCKET)) % PAD_BUCKET;
    (out.meta as WfStateMeta)[PAD_KEY] = "x".repeat(fill);
    return out;
  };
  const clean = (state: WfState): WfState => {
    const { [PAD_KEY]: _pad, ...meta } = (state.meta ?? {}) as WfStateMeta;
    return { ...state, meta };
  };
  const wrapped: WfStateStrategy = {
    persist: (state, options, overrides) =>
      strategy.persist(tagged(state, options), options, overrides),
    retrieve: async (token) => {
      const state = await strategy.retrieve(token);
      return accepts(state) ? clean(state) : null;
    },
    consume: async (token) => {
      if (!accepts(await strategy.retrieve(token))) return null;
      const state = await strategy.consume(token);
      return accepts(state) ? clean(state) : null;
    },
  };
  // The strategy it wraps — for introspection (tests, diagnostics).
  Object.defineProperty(wrapped, "inner", { value: strategy });
  if (strategy.persistEntry) {
    wrapped.persistEntry = (state, options, overrides) =>
      strategy.persistEntry!(tagged(state, options), options, overrides);
  }
  if (strategy.consumeEntry) {
    wrapped.consumeEntry = async (token) => {
      if (!accepts(await strategy.retrieve(token))) return null;
      const entry = await strategy.consumeEntry!(token);
      return entry && accepts(entry.state) ? { ...entry, state: clean(entry.state) } : null;
    };
  }
  return wrapped;
}

const HOOK_NAMES = [
  "around",
  "beforePersist",
  "renderEnvelope",
  "restoreOnError",
  "maxRestores",
] as const satisfies ReadonlyArray<keyof WfOutletTriggerConfig>;

/**
 * Workflow-trigger hooks passed through to the wooks trigger
 * (`handleWfOutletRequest`). Set them app-wide by overriding
 * {@link WfTriggerProvider.triggerHooks}, or per route on `@WfTrigger(...)`
 * (a route's hook replaces the provider's hook of the same name).
 *
 * - `around(run)` — wraps everything the request does to workflow state and
 *   the outside world (access checks, consume/start/resume, `beforePersist`,
 *   persist, outlet delivery), e.g. `(run) => db.transaction(run)`. It may
 *   call `run()` again after a failure; each run starts over from the request.
 * - `beforePersist(state, pause)` — runs right before a paused state is
 *   persisted, inside `around`; throw to abort (nothing persisted, no delivery).
 *   `AuthWorkflow`'s rendered `ctx.public` projection is already stripped
 *   from `state.context` then (it is never persisted).
 * - `renderEnvelope(envelope, info)` — maps every body the trigger answers
 *   with (paused envelopes and finished values), e.g. to translate texts.
 * - `restoreOnError` — opt-in (default off): when a resume fails after its
 *   token was consumed, put the pre-step state back under the same token so
 *   the link can be retried (at most `maxRestores` times, default 3, never
 *   extending its lifetime). Needs a durable strategy that reports expiries
 *   (`HandleStateStrategy`); it rolls back everything the step wrote to the
 *   workflow context. Leave it off for steps with side effects that must not
 *   run twice. Set provider-wide, it also covers the bundled credential steps
 *   (set password, recovery reset, MFA enrolment) — prefer enabling it per
 *   route, or a predicate that accepts only transient store errors. The
 *   bundled password forms refuse a restored state once the password changed.
 */
export type WfTriggerHooks = Pick<WfOutletTriggerConfig, (typeof HOOK_NAMES)[number]>;

/** Per-request options of {@link WfTriggerProvider.handle} (what `@WfTrigger(...)` passes). */
export interface WfTriggerOpts extends WfTriggerHooks {
  /**
   * Workflow ids this trigger may START and RESUME (a leading `/` is ignored).
   * Omitted = unrestricted; `[]` = deny every workflow. A flow is judged by
   * the registered flow a request resolves to (an `onNotFound` flow or a
   * parametric route that catches the id counts as that flow), and an entry
   * admits only a flow registered under exactly that id. A refused start
   * answers 403 `AOOTH_WORKFLOW_NOT_ALLOWED`, a refused resume 403
   * `AOOTH_WORKFLOW_RESUME_NOT_ALLOWED`; a state token minted for a workflow
   * outside the list is not consumed.
   */
  allow?: string[];
  /**
   * Workflow ids this trigger may RESUME but never START — e.g. a public
   * trigger that continues an invite flow only an admin can issue. Additive to
   * `allow` (a resume needs no `allow` entry); a start is refused (403
   * `AOOTH_WORKFLOW_NOT_ALLOWED`) even when `allow` lists the flow. `block`
   * still wins.
   */
  resumeOnly?: string[];
  /**
   * Workflow ids this trigger refuses on start AND resume (403
   * `AOOTH_WORKFLOW_NOT_ALLOWED` on a start, `AOOTH_WORKFLOW_RESUME_NOT_ALLOWED`
   * on a resume), whatever `allow` / `resumeOnly` say. An entry also blocks the
   * flow it resolves to (`'user/42'` blocks `'user/:id'`).
   */
  block?: string[];
  /** Per-endpoint token wire override. Defaults to the provider's wire (`{read:['body','query','cookie'], write:'body', name:'wfs'}`). */
  token?: WfOutletTokenConfig;
}

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

/**
 * The access refusals the wooks trigger raises, in aooth's public form. The
 * engine decides (`allow` / `resumeOnly` / `block`, judged on the resolved
 * flow); aooth keeps its own wire contract:
 *
 * - `WF_FORBIDDEN` (403) on a start becomes `AOOTH_WORKFLOW_NOT_ALLOWED` (403,
 *   `workflow` param). On a resume the engine never names the stored flow, so
 *   it becomes `AOOTH_WORKFLOW_RESUME_NOT_ALLOWED` (403, no params, a template
 *   without a placeholder).
 * - `WF_NOT_FOUND` (404) — a start whose id resolves to no flow while access
 *   lists are set — becomes `AOOTH_WORKFLOW_NOT_ALLOWED` (403) whenever `allow`
 *   is set: unregistered ids answer like unlisted ones, so a probe cannot tell
 *   which ids `allow` lists. With only `resumeOnly` / `block` set it stays 404.
 *
 * Anything else passes through untouched. The error is recognised by its body
 * code, not by class, so a second installed copy of `@wooksjs/event-http` does
 * not let a raw `WF_FORBIDDEN` through.
 */
function mapRefusal(error: unknown, allowed: boolean): unknown {
  const body = (error as { body?: Partial<WfTriggerErrorBody> } | null)?.body;
  if (!body || typeof body !== "object") return error;
  const wfid = typeof body.params?.wfid === "string" ? normalizeWfId(body.params.wfid) : undefined;
  if (body.code === "WF_FORBIDDEN") {
    return wfid === undefined
      ? aoothHttpError(403, "AOOTH_WORKFLOW_RESUME_NOT_ALLOWED")
      : aoothHttpError(403, "AOOTH_WORKFLOW_NOT_ALLOWED", { workflow: wfid });
  }
  if (body.code === "WF_NOT_FOUND" && allowed && wfid !== undefined) {
    return aoothHttpError(403, "AOOTH_WORKFLOW_NOT_ALLOWED", { workflow: wfid });
  }
  return error;
}

/**
 * Run one trigger attempt. The invite outlet reads the link callback from a
 * slot reserved on the HTTP event; it is reserved per run, so a run that
 * `around` retries starts clean. Access refusals leave in aooth's form
 * ({@link mapRefusal}).
 */
async function runTrigger(run: () => Promise<unknown>, allowed: boolean): Promise<unknown> {
  reservePendingInviteLink();
  try {
    return await run();
  } catch (error) {
    throw mapRefusal(error, allowed);
  }
}

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
@Injectable()
export class WfTriggerProvider {
  /**
   * Outlets the trigger can pause on: HTTP (forms), `invite` (the link of
   * `AuthWorkflowOpts.inviteDelivery: 'deliver' | 'return-link'`) and
   * `magic-link` (recovery and sign-in links — it sends through the `email`
   * outlet). Append an `email` outlet (`createAuthEmailOutlet`) for the default
   * invite delivery and for magic links.
   */
  protected outlets: WfOutlet[] = [
    createAsHttpOutlet(),
    createInviteOutlet(),
    createMagicLinkOutlet(() => this.outlets.find((o) => o.name === "email")),
  ];
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
    return this.auth.deriveStateKey(WF_STATE_KEY_LABEL);
  }

  /**
   * Secret that keys the digests of one-time codes (recovery, sign-in, signup
   * and enrolment codes) held in workflow state — the state keeps a keyed
   * digest of each code, never the code. Default: the wf-state secret, so a
   * store-backed setup that overrides `wfStateSecret()` needs nothing more.
   * All instances must agree on it.
   */
  protected pincodeSecret(): string | Buffer {
    return this.wfStateSecret();
  }

  private cachedPincodeKey?: Buffer;

  /**
   * The key of the one-time-code digests this provider publishes on every
   * request: {@link derivePincodeKey} of {@link pincodeSecret}. With the
   * default secrets it equals what `AuthWorkflow.pincodeKey()` derives outside
   * a provider (`defaultPincodeKey`).
   */
  protected pincodeKey(): Buffer {
    return (this.cachedPincodeKey ??= derivePincodeKey(this.pincodeSecret()));
  }

  /** TTL (ms) for encapsulated pre-validation tokens. Default: undefined = no TTL (token valid until used), so an idle login form never expires server-side. */
  protected wfStateEncapsulatedTtlMs(): number | undefined {
    return undefined;
  }

  /** Durable strategy a workflow swaps to after the first validated input. Default = encapsulated (no real store); customers override to return e.g. new HandleStateStrategy({ store: <redis/db> }). */
  protected storeStrategy(): WfStateStrategy {
    return this.makeEncapsulated();
  }

  /**
   * Store of the magic-link pauses (recovery and sign-in links). Default: one
   * in-memory store per provider — single process only. With several
   * instances, return a shared `WfStateStore` (e.g. the `AsWfStore` of your
   * wf-state table). The strategy around it is fixed: handles are stored
   * hashed (a read of the store yields no usable link), each link is consumed
   * by its first use, and it expires with the link (`magicLinkTtlMs`).
   */
  protected magicLinkStore(): WfStateStore {
    return (this.defaultMagicLinkStore ??= new BoundedWfStateStoreMemory());
  }

  private defaultMagicLinkStore?: WfStateStore;

  private makeEncapsulated(): WfStateStrategy {
    return new EncapsulatedStateStrategy({
      secret: this.wfStateSecret(),
      defaultTtl: this.wfStateEncapsulatedTtlMs(),
    });
  }

  /**
   * App-wide workflow-trigger hooks ({@link WfTriggerHooks}): `around`,
   * `beforePersist`, `renderEnvelope`, `restoreOnError` / `maxRestores`.
   * Default: none. A route's `@WfTrigger({...})` option of the same name
   * replaces the hook returned here. Called once per trigger request.
   *
   * ```ts
   * protected override triggerHooks(): WfTriggerHooks {
   *   return { around: (run) => db.transaction(run) };
   * }
   * ```
   */
  protected triggerHooks(): WfTriggerHooks {
    return {};
  }

  private cachedState?: StateRegistry;

  /** Named strategy registry: every wf starts on `encapsulated` (default); a step calls swapStrategy('store') to move durable, and a magic-link pause swaps to `magic-link`. Built lazily so subclass overrides (storeStrategy/wfStateSecret/magicLinkStore) are in effect. */
  protected stateRegistry(): StateRegistry {
    if (!this.cachedState) {
      this.cachedState = {
        strategies: {
          encapsulated: tagStrategy("encapsulated", this.makeEncapsulated()),
          store: tagStrategy("store", this.storeStrategy()),
          [MAGIC_LINK_STRATEGY]: tagStrategy(
            MAGIC_LINK_STRATEGY,
            new HandleStateStrategy({ store: this.magicLinkStore(), hashHandles: true }),
          ),
        },
        default: "encapsulated",
      };
    }
    return this.cachedState;
  }

  /**
   * Read the paused workflow state a resume token (`wfs`) points at, WITHOUT
   * consuming it — e.g. to show what a link is for before its holder acts.
   * The token is resolved exactly as a resume resolves it (its strategy
   * prefix, the strategy's handle hashing and legacy-key rules, the strategy
   * tag), so a peek finds what a resume would. An unknown, expired, malformed
   * or foreign token is `null` — one answer for all. The state carries
   * server-only context: project what you need, never send it as-is.
   */
  async peek(token: string): Promise<WfState | null> {
    const i = token.indexOf(".");
    if (i <= 0 || i === token.length - 1) return null;
    const strategies = this.stateRegistry().strategies;
    const name = token.slice(0, i);
    if (!Object.hasOwn(strategies, name)) return null;
    return strategies[name].retrieve(token.slice(i + 1));
  }

  /**
   * Handle one trigger request. `opts` is {@link WfTriggerOpts}: the access
   * lists are judged by the wooks trigger before a state token is consumed, and
   * hooks set in `opts` replace the {@link triggerHooks} of the same name.
   */
  async handle(opts: WfTriggerOpts = {}): Promise<unknown> {
    const wfApp = this.wf.getWfApp();
    current().set(pincodeKeySlot, this.pincodeKey());
    const deps: WfOutletTriggerDeps = {
      // Forward `o.strategy` — the trigger resolves the registry default (start)
      // or the incoming token's prefix (resume) and passes it here; the wf
      // adapter sets the `wf.strategyName` slot from it, which the trigger then
      // reads back at pause time. Dropping it leaves the slot unset and the
      // trigger throws `Key "wf.strategyName" is not set` on every request.
      // `expectSchemaId` is the flow the access lists judged: run nothing else.
      start: (schemaId, context, o) =>
        wfApp.start(schemaId, context, {
          input: o?.input,
          eventContext: (o?.eventContext ?? current()) as never,
          strategy: o?.strategy,
          expectSchemaId: o?.expectSchemaId,
        }),
      resume: (state, o) =>
        wfApp.resume(state, {
          input: o?.input,
          eventContext: (o?.eventContext ?? current()) as never,
          strategy: o?.strategy,
        }),
      // The access lists judge the flow a request resolves to, not its spelling.
      resolveSchemaId: (id, o) => this.wf.resolveSchemaId(id, o as never),
    };
    // Only the hook options pass through — never other trigger config (state,
    // outlets…) a subclass might return by mistake.
    const base = this.triggerHooks();
    const hooks: Record<string, unknown> = {};
    for (const name of HOOK_NAMES) {
      const value = opts[name] ?? base[name];
      if (value !== undefined) hooks[name] = value;
    }
    // Strip `AuthWorkflow`'s rendered `ctx.public`, then run the app's hook.
    const beforePersist = opts.beforePersist ?? base.beforePersist;
    hooks.beforePersist = (state: WfState, pause: WfPauseRequest) => {
      state.context = withoutPublicProjection(state.context);
      return beforePersist?.(state, pause);
    };
    const around = opts.around ?? base.around;
    const { allow, resumeOnly, block } = opts;
    const attempt = (run: () => Promise<unknown>) => runTrigger(run, allow !== undefined);
    return handleAsOutletRequest(
      {
        ...hooks,
        allow,
        resumeOnly,
        block,
        around: around ? (run) => around(() => attempt(run)) : attempt,
        state: this.stateRegistry(),
        outlets: this.outlets,
        token: opts.token ?? this.token,
      },
      deps,
    );
  }
}
