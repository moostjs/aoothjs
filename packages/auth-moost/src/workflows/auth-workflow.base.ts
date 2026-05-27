/**
 * Shared helpers for the three bundled auth workflows
 * (`LoginWorkflow` / `InviteWorkflow` / `RecoveryWorkflow`). Holds the
 * auth-specific glue (`requireUsername`, `withStoreErrorTranslation`),
 * the pincode primitives (`mintPin`, `verifyPin`), and the HTTP-context
 * `resolveClientIp()` reader. Workflows extend this class and call helpers
 * via `this.<name>(...)`.
 */
import {
  generateTotpSecret,
  generateTotpUri,
  maskEmail,
  maskPhone,
  type TransferablePolicy,
  UserAuthError,
  type UserService,
} from "@aooth/user";
import { useAtscriptWf } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { Step, type TWorkflowSchema, WorkflowParam } from "@moostjs/event-wf";
import { useRequest } from "@wooksjs/event-http";

import { Public } from "../auth.decorator";
import type { ConsentStore } from "../consent.store";

/**
 * Method names for the MFA enrollment helper. Re-exported from
 * `login.workflow.options` as `MfaTransport` (kept as the public alias) so
 * existing consumers don't need to switch import paths.
 */
export type MfaTransport = "sms" | "email" | "totp";

// ── Shared WF context base ──
//
// Each bundled auth workflow ctx (`LoginWfCtx`, `InviteWfCtx`,
// `RecoveryWfCtx`) extends `AuthWfCtxBase`. The thematic groups below
// (`consents`, `pincode`, `mfaEnroll`, `password`, `completion`, `public`)
// give the three workflows a near-identical top-level shape; WF-specific
// fields are added by each subclass's interface. Each group key here is
// either `@wf.context.pass`-able individually (when forms.as needs to ship
// that group to the UI) OR strictly server-only (`pin`, `aborted`).
//
// Helper consumption: helpers on `AuthWorkflowBase` take narrower
// structural subsets (e.g. `MfaEnrollCtx`, `PinCtx`, `InlineConsentCtx`)
// so they stay workflow-agnostic and don't depend on the full ctx union.

/**
 * Consents — both server state (`accepted` / `decidedAt`) and the UI-visible
 * descriptor list (`pending` / `persisted`). The whole group is shipped to
 * forms via `@wf.context.pass 'consents'`; client cannot forge audit rows
 * because `processInlineConsent` reads `pending` server-side as the
 * authoritative whitelist.
 */
export interface AuthWfConsentsState {
  pending?: ConsentDescriptorLike[];
  accepted?: string[];
  decidedAt?: number;
  persisted?: boolean;
}

/**
 * Pincode UI hint — masked recipient + UI cooldown timer, shipped via
 * `@wf.context.pass 'pincode'`. The pincode VALUE itself stays out of this
 * group (server-only `ctx.pin` / `ctx.pinExpire`) so it never reaches the
 * client.
 */
export interface AuthWfPincodeUiState {
  sentTo?: string;
  timeout?: number;
}

/**
 * MFA enrollment running state. Shared by `LoginWorkflow` and
 * `InviteWorkflow`; recovery doesn't enrol new factors but the field stays
 * optional on the base for shape symmetry. Shipped via
 * `@wf.context.pass 'mfaEnroll'` (TOTP secret + URI are surfaced so the
 * UI can render the QR code).
 */
export interface AuthWfMfaEnrollState {
  method?: MfaTransport;
  address?: string;
  secret?: string;
  uri?: string;
  availableTransports?: MfaTransport[];
  /**
   * Policy mode for the picker form — `'required'` hides the skip action,
   * `'optional'` shows it. Mirrors the helper's `deps.mode` so the form
   * can reach the same decision via `ctx.mfaEnroll.mode`.
   */
  mode?: "required" | "optional";
  done?: boolean;
  pincodeCooldown?: number;
}

/**
 * Password-change UI hints. `policies` is the wire-shape returned by
 * `UserService.getTransferablePolicies()` — `string`-expression rules
 * evaluatable client-side via `@prostojs/ftring`. Shipped via
 * `@wf.context.pass 'password'`.
 */
export interface AuthWfPasswordUiState {
  policies?: TransferablePolicy[];
  changeReason?: "initial" | "expired";
  heading?: string;
  intro?: string;
}

/**
 * Completion outcome — set by post-pause finishing steps; shipped via
 * `@wf.context.pass 'completion'` if a final-confirm form needs to read
 * `tokensIssued` / `redirectUrl`.
 */
export interface AuthWfCompletionState {
  passwordChanged?: boolean;
  tokensIssued?: boolean;
  redirectUrl?: string;
}

/**
 * Miscellaneous UI-shared bag for fields that don't fit a thematic group.
 * Each WF extends this with its own fields (e.g. `LoginPublic` adds
 * `altForgotPassword` etc.). Shipped via `@wf.context.pass 'public'`.
 */
export interface AuthWfPublicBase {}

/**
 * Base shape shared by all three auth workflow ctx interfaces. Concrete
 * `LoginWfCtx` / `InviteWfCtx` / `RecoveryWfCtx` extend this and add
 * WF-specific top-level fields (policy groups, per-WF flags) alongside the
 * shared groups below.
 */
export interface AuthWfCtxBase {
  /** Bound by `credentials` / `init` once the user is identified. */
  username?: string;
  /** Optional secondary identifier — login + recovery use it for routing. */
  email?: string;

  /** Server-only pincode secret (NEVER `@wf.context.pass`-ed). */
  pin?: string;
  /** Server-only pincode expiry (NEVER `@wf.context.pass`-ed). */
  pinExpire?: number;

  /** Server-only abort flag — schema gates short-circuit when set. */
  aborted?: boolean;

  consents?: AuthWfConsentsState;
  pincode?: AuthWfPincodeUiState;
  mfaEnroll?: AuthWfMfaEnrollState;
  password?: AuthWfPasswordUiState;
  completion?: AuthWfCompletionState;
  public?: AuthWfPublicBase;
}

/**
 * Context shape consumed by the `enrollPickPhase` / `enrollAddressPhase` /
 * `enrollConfirmPhase` helpers. Both `LoginWfCtx` and
 * `InviteWfCtx` extend this implicitly (they declare the same field set).
 * Kept structural so neither workflow's full ctx union has to be imported
 * here — base stays workflow-agnostic.
 */
export interface MfaEnrollCtx {
  enrollMethod?: MfaTransport;
  enrollAddress?: string;
  enrollSecret?: string;
  enrollUri?: string;
  enrollAvailableTransports?: MfaTransport[];
  enrollDone?: boolean;
  pin?: string;
  pinExpire?: number;
  pinSentTo?: string;
  /**
   * Next-allowed-resend timestamp for the Phase 3 confirm pincode (sms/email
   * only). Written by the Phase 2 initial send + the Phase 3 `resend`
   * alt-action; consulted by `resend` to throttle re-emits. Mirrors the
   * `pinTimeout` pattern used by the login `pincode-check-login` step.
   */
  enrollPincodeCooldown?: number;
}

/**
 * Looser structural mirror of `DeliverPayload` from `login.workflow.ts`.
 * The base file mustn't import from a sibling workflow file; the concrete
 * workflow's strict discriminated union is structurally assignable to this.
 */
export interface DeliverPayloadLike {
  channel: "email" | "sms";
  kind: string;
  recipient: string;
  code?: string;
  expiresAt?: number;
  ttlMs?: number;
  userId?: string;
}

export interface MfaEnrollDeps {
  ctx: MfaEnrollCtx;
  username: string;
  users: UserService;
  /** Concrete workflow's `deliver` hook, narrowed to the payloads this flow emits. */
  deliver: (payload: DeliverPayloadLike) => Promise<void>;
  forms: {
    pickMethod: TAtscriptAnnotatedType;
    address: TAtscriptAnnotatedType;
    confirm: TAtscriptAnnotatedType;
  };
  transports: MfaTransport[];
  pincodeLength: number;
  pincodeTtlMs: number;
  /**
   * Per-method resend cooldown for the Phase 3 confirm pincode (sms/email).
   * Mirrors `LoginWorkflowOpts.mfa.pincodeResendTimeoutMs`.
   */
  pincodeResendTimeoutMs: number;
  /** TOTP provisioning issuer (rendered in the authenticator app). */
  issuer: string;
  /**
   * Enrollment policy. `'required'` runs through all 3 phases. `'optional'`
   * additionally watches for a `skip` action on the Phase 1 pickMethod form —
   * a skip click short-circuits by setting `ctx.enrollDone = true`. The
   * caller is expected to gate this step out entirely when `mode === 'disabled'`.
   */
  mode: "required" | "optional";
  /**
   * Optional bridge fired at the end of `enrollConfirmPhase` (or on a skip in
   * `'optional'` mode at any phase) — right after `enrollDone` flips true. Login
   * uses this to mirror `enrollDone` → `mfaChecked` so its outer MFA while-loop
   * (gated on `!mfaChecked`) exits. Invite omits it because its enrollment
   * while-loop is gated on `!enrollDone` directly.
   */
  onComplete?: (ctx: MfaEnrollCtx) => void;
}

/**
 * Top-level `UserCredentials` keys that workflow-collected profile payloads
 * MUST NEVER carry through to persistence. The server sets these out-of-band
 * (admin-supplied `ctx.roles`, password-set step, account activation, MFA
 * enrolment elsewhere). If the consumer's `.as` profile form mistakenly
 * declares one — or an attacker submits one as an extra field — the
 * strip applied at the workflow step (NOT at the `applyProfile` override
 * seam) blocks shadowing.
 *
 * Shared between `InviteWorkflow.applyProfileStep` (audit hole #6) and
 * `LoginWorkflow.profileComplete` (audit hole #15 Sink A). The strip lives
 * at the workflow step so consumer subclasses that replace `applyProfile`
 * with a different storage path (e.g. external CRM) still receive a
 * sanitized payload.
 */
export const RESERVED_USER_KEYS: ReadonlySet<string> = new Set<string>([
  "roles",
  "version",
  "id",
  "username",
  "account",
  "password",
  "passwordHistory",
  "mfa",
  "trustedDevices",
  "pendingInvitation",
]);

/**
 * Return a shallow copy of `profile` with `RESERVED_USER_KEYS` removed.
 * Does not mutate the input.
 */
export function stripReservedUserKeys(profile: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(profile)) {
    if (!RESERVED_USER_KEYS.has(key)) out[key] = profile[key];
  }
  return out;
}

/** Workflow context shape expected by `mintPin` + `verifyPin`. */
interface PinCtx {
  pin?: string;
  pinExpire?: number;
}

/**
 * Structural ctx shape consumed by `processInlineConsent`. Mirrors the
 * relevant subset of the workflow ctx types so the helper stays
 * workflow-agnostic. The helper consumes only the dynamic
 * `consents.pending` descriptor array (populated by `prepare-consents`
 * from `ConsentStore.getPendingConsents()`) and the per-run booking
 * fields it writes back onto `ctx.consents` — the prior static
 * `acceptance` / `termsVersion` branches were retired in Phase 6
 * along with the matching `ctx.acceptance` field on each workflow
 * ctx type.
 */
export interface InlineConsentCtx {
  /**
   * Group state for the inline consent block. `pending` is the
   * server-owned whitelist seeded by `prepare-consents`; `accepted`
   * and `decidedAt` are set by `processInlineConsent` after silent-
   * dropping unknown ids; `persisted` is flipped by `persist-consents`
   * after the batched `consentStore.save` call.
   */
  consents?: AuthWfConsentsState;
}

/**
 * Structural alias of `ConsentDescriptor` — kept inline so this module
 * doesn't import from `../consent.store.ts` (which would create a cycle:
 * consent.store.ts already imports `ConsentEvent` from here). Exported
 * because `AuthWfConsentsState` (above) is part of the public surface.
 */
export interface ConsentDescriptorLike {
  id: string;
  text: string;
  required?: string;
  version?: string;
}

/**
 * Subset of the carrier-form payload that `processInlineConsent` reads.
 * Phase 5 replaces the pre-existing static `{ acceptedTerms?, marketingOptIn? }`
 * pair with a single dynamic `consents: string[]` — the SUBSET of descriptor
 * ids the user ticked in the `AsConsentArray` (`@atscript/vue-aooth`)
 * component. The server reads `ctx.consents.pending` from its own ctx (NOT
 * from this input) to decide which ids are valid; unknown ids are silently
 * dropped (audit-grade defense — see helper rationale).
 */
export interface InlineConsentInput {
  consents?: string[];
}

/**
 * Consent event emitted to the `ConsentStore.save(username, events)` DI
 * provider. Storage shape is intentionally the consumer's call — Mongo users
 * typically push the events onto an embedded array, SQL users insert into an
 * audit table, event-bus users publish to a topic. The library batches all
 * collected events from a single workflow run into one call: ONE event per
 * pending descriptor (audit-friendly default — declined-optional consents
 * are persisted too, so customers can prove the user was asked; customers
 * who want only accepted events filter in their `save()` override). The
 * `accepted` boolean is explicit per row — `true` when the user ticked the
 * matching descriptor, `false` when an optional descriptor went un-ticked.
 */
export interface ConsentEvent {
  /** Identifier from the matching `ConsentDescriptor.id`. */
  id: string;
  /** Whether the user ticked this descriptor (`false` for un-ticked optionals). */
  accepted: boolean;
  /** Stamped from the matching `ConsentDescriptor.version` (when set). */
  version?: string;
  /**
   * Wall-clock ms at the moment `processInlineConsent` resolved the user's
   * carrier-form submission (NOT at write-time — captured BEFORE the batched
   * `consentStore.save` call so a paused-workflow resume gap doesn't drift
   * the timestamp).
   */
  at: number;
}

/**
 * Structural alias for `ReturnType<typeof useAtscriptWf>` — only the
 * `requireInput` method is consumed by `processInlineConsent`, kept narrow
 * so callers can pass any form's wf handle without TS choking on the form-
 * specific `resolveInput` return type.
 */
type WfRequireInputOnly = {
  requireInput(opts?: { errors?: Record<string, string>; formMessage?: string }): unknown;
};

/**
 * Shared base for the three bundled auth workflows. `abstract` because
 * `consentStore` is consumed by the inherited `persistConsentsStep` @Step
 * but is supplied by each subclass's constructor (DI-injected). Concrete
 * subclasses already declare `protected readonly consentStore: ConsentStore`,
 * which structurally satisfies the abstract getter.
 */
export abstract class AuthWorkflowBase {
  /**
   * `ConsentStore` access for inherited `persistConsentsStep`. Subclasses
   * supply this via their constructor-initialized `protected readonly
   * consentStore: ConsentStore` field — TypeScript treats the field as
   * satisfying this abstract getter.
   */
  protected abstract get consentStore(): ConsentStore;

  /**
   * Workflow ID tag passed to `ConsentStore.getPendingConsents(...)` by the
   * inherited `prepareConsents` @Step. Customer impls key consent history by
   * (user, workflow) so each WF must declare its own canonical id. Subclasses
   * override this as a one-line getter, e.g. `protected get consentsWorkflowId() { return "auth/login/flow"; }`.
   */
  protected abstract get consentsWorkflowId(): string;

  /**
   * Asserts `ctx.username` is populated. Workflow steps reach for `ctx.username`
   * after `credentials`/`init` has set it; losing it indicates a workflow-state
   * bug, not a client error. Throws `HttpError(500)` on miss; otherwise narrows
   * the field to `string` for the caller via `asserts`.
   */
  protected requireUsername<T extends { username?: string }>(
    ctx: T,
  ): asserts ctx is T & { username: string } {
    if (!ctx.username) throw new HttpError(500, "Workflow state corrupted: missing username");
  }

  /**
   * Wrap an `UserStore` mutation that can race (`withCas`-backed paths:
   * `addMfaMethod`, `confirmMfaMethod`, `addTrustedDevice`) so a CAS
   * retry-budget exhaustion surfaces as 409 Conflict — the canonical OCC
   * status — rather than bubbling to the moost default 500. Client SHOULD
   * retry; a 500 falsely implies the server is broken. Other `UserAuthError`
   * shapes pass through unchanged so step-local catch blocks (e.g. ALREADY_EXISTS
   * → 409 with a different reason) still see them.
   */
  protected async withStoreErrorTranslation<T>(op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "CAS_EXHAUSTED") {
        throw new HttpError(409, err.message);
      }
      throw err;
    }
  }

  /**
   * Resolve the client IP from the active HTTP request, swallowing the case
   * where there is no HTTP context (unit tests that hand-roll the wf runtime).
   */
  protected resolveClientIp(): string | undefined {
    try {
      return useRequest().getIp() || undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Mint a numeric pincode and stash it + its expiry onto `ctx`. Returns the
   * code so the caller can hand it to the delivery transport.
   */
  protected mintPin(ctx: PinCtx, length: number, ttlMs: number): string {
    let code = "";
    for (let i = 0; i < length; i++) code += Math.floor(Math.random() * 10).toString();
    ctx.pin = code;
    ctx.pinExpire = Date.now() + ttlMs;
    return code;
  }

  /**
   * Verify a submitted pincode against `ctx.pin`. Returns a `{ code: '…' }`
   * error map on expired/invalid, or `null` on success. Callers wrap the result
   * with `useAtscriptWf(PincodeForm).requireInput({ errors })`.
   */
  protected verifyPin(ctx: PinCtx, submitted: string | undefined): { code: string } | null {
    if (!ctx.pin || !ctx.pinExpire || Date.now() > ctx.pinExpire) return { code: "Code expired" };
    if (submitted !== ctx.pin) return { code: "Invalid code" };
    return null;
  }

  /**
   * Validate + stash inline-consent fields submitted on a carrier form.
   *
   * SECURITY (silent-drop): the server reads its OWN `ctx.consents.pending`
   * (set once by `prepare-consents` from `ConsentStore.getPendingConsents()`)
   * as the authoritative whitelist of valid descriptor ids. Any id in the
   * user-submitted `input.consents` array that does NOT match a current
   * pending descriptor is SILENTLY DROPPED — no error, no log, no signal
   * back to the client. This preserves the audit-grade
   * "what user saw is what server records" invariant: an attacker
   * submitting `consents: ['terms', 'gdpr-forged-id']` against a descriptor
   * list of only `['terms']` cannot forge an audit record for the
   * never-displayed `'gdpr-forged-id'` consent. Surfacing the drop would
   * leak the consent universe (probing surface), so the defense is silent.
   *
   * SECURITY (mandatory-by-message): each descriptor's `required` field is
   * the load-bearing mandatory flag. A non-empty string means the consent
   * is MANDATORY and that string IS the per-row error message — the
   * `AsConsentArray` component surfaces it inline per descriptor; the
   * server throws the SAME copy as a form-level error on the bound
   * `consents` field when the first required descriptor is missing from
   * the submitted set. Absent / empty `required` ⇒ optional consent — the
   * un-ticked descriptor is still persisted as `{accepted: false}` (audit
   * default — proves the user was asked).
   *
   * Idempotency: once `ctx.consents.persisted` is true, the helper is a
   * no-op. Same for `ctx.consents.pending` being empty / unset — no
   * pending = nothing to validate (the carrier-form's `AsConsentArray`
   * also self-hides on empty `pending`).
   */
  protected processInlineConsent(
    ctx: InlineConsentCtx,
    input: InlineConsentInput,
    wf: WfRequireInputOnly,
  ): void {
    if (ctx.consents?.persisted) return;
    // Already-collected guard: a later carrier form on the same workflow
    // run MUST NOT re-validate consents (the user already ticked them on
    // the FIRST carrier form). Without this, ProfileCompleteForm's
    // inherited `consents` field would re-run required-checks against the
    // empty form payload and throw, breaking multi-carrier-form flows.
    if (ctx.consents?.decidedAt !== undefined) return;
    const pending = ctx.consents?.pending ?? [];
    if (pending.length === 0) return;
    // Server-side whitelist of valid ids. Any client-submitted id outside
    // this set is silently dropped (see SECURITY block above).
    const validIds = new Set(pending.map((p) => p.id));
    const submitted = new Set<string>();
    for (const id of input.consents ?? []) {
      if (validIds.has(id)) submitted.add(id);
    }
    // First missing-required descriptor wins the form-level error. The
    // string IS the error copy — customer-defined per descriptor (the
    // `AsConsentArray` UI component surfaces the same string per row via
    // `errorFor`; the server form-level error here is belt-and-brace for
    // hand-rolled HTTP clients that bypass the SPA).
    for (const p of pending) {
      if (p.required && !submitted.has(p.id)) {
        throw wf.requireInput({ errors: { consents: p.required } });
      }
    }
    const group = (ctx.consents ??= {});
    group.accepted = [...submitted];
    group.decidedAt = Date.now();
  }

  /**
   * Batched consent persistence — shared `persist-consents` step body for
   * `LoginWorkflow` / `InviteWorkflow` / `RecoveryWorkflow`. Fans one
   * `ConsentEvent` per pending descriptor out to the `ConsentStore.save`
   * DI provider in a single call. Audit-friendly default: declined-optional
   * consents are persisted with `accepted: false` (customers who want only
   * accepted events filter in their `save()` override). `accepted` is
   * derived per descriptor by `consents.accepted.has(id)`. Idempotent via
   * `ctx.consents.persisted`; short-circuits with no events when
   * `ctx.consents.pending` is empty (defensive — the schema condition gates on
   * `ctx.consents.decidedAt` which is only set when pending was non-empty).
   *
   * Invoked by the inherited `@Step("persist-consents")` `persistConsentsStep`
   * method below — kept as a separate helper so subclass tests that override
   * `persistConsentsStep` can still call this body via `super`.
   */
  protected async runPersistConsents(
    ctx: InlineConsentCtx & AuthWfCtxBase,
    consentStore: ConsentStore,
  ): Promise<undefined> {
    this.requireUsername(ctx);
    const group = (ctx.consents ??= {});
    if (group.persisted) return undefined;
    const pending = group.pending ?? [];
    if (pending.length === 0) {
      group.persisted = true;
      return undefined;
    }
    const accepted = new Set(group.accepted ?? []);
    const at = group.decidedAt ?? Date.now();
    const events: ConsentEvent[] = pending.map((p) => {
      const evt: ConsentEvent = { id: p.id, accepted: accepted.has(p.id), at };
      if (p.version !== undefined) evt.version = p.version;
      return evt;
    });
    await consentStore.save(ctx.username, events);
    group.persisted = true;
    return undefined;
  }

  /**
   * Batched consent persistence — inherited by `LoginWorkflow` /
   * `InviteWorkflow` / `RecoveryWorkflow` via their class-level `@Inherit()`.
   * Per Mate's PROP inheritance rule, this decoration flows down only when
   * the subclass has no own metadata on `persistConsentsStep` AND its
   * `classMeta.inherit` is set. Both conditions are load-bearing for the
   * wf engine to register `persist-consents` under each subclass's
   * controller prefix.
   *
   * `@Public()` is applied here so the step bypasses arbac on all three
   * subclasses uniformly — login + recovery are class-level `@Public()`
   * already (the per-method decoration is redundant but harmless),
   * invite is NOT class-level `@Public()` and relies on this method-level
   * decoration to opt the step out of arbac (consent persistence runs on
   * the anonymous magic-link resume tail).
   */
  @Step("persist-consents")
  @Public()
  persistConsentsStep(
    @WorkflowParam("context") ctx: InlineConsentCtx & AuthWfCtxBase,
  ): Promise<undefined> {
    return this.runPersistConsents(ctx, this.consentStore);
  }

  /**
   * Loads pending consents for the bound user — inherited by the three
   * bundled WFs via class-level `@Inherit()` (same mechanics as
   * `persistConsentsStep` above). The WF-ID tag passed to the consent store
   * is declared per-subclass via the `consentsWorkflowId` abstract getter
   * (login: "auth/login/flow", invite: "auth/invite/start", recovery:
   * "auth/recovery/flow"). `@Public()` here for the same reason as on
   * `persistConsentsStep`.
   *
   * `if (!ctx.username)` is belt-and-brace — the schema places this step
   * AFTER the `!ctx.username` break gate, but future schema refactors that
   * re-order steps would otherwise hit the consent store with an unbound
   * username.
   */
  @Step("prepare-consents")
  @Public()
  prepareConsents(
    @WorkflowParam("context") ctx: InlineConsentCtx & AuthWfCtxBase,
  ): undefined | Promise<undefined> {
    if (!ctx.username) return undefined;
    const result = this.consentStore.getPendingConsents(ctx.username, {
      workflow: this.consentsWorkflowId,
    });
    if (result instanceof Promise) {
      return result.then((resolved) => {
        (ctx.consents ??= {}).pending = resolved;
        return undefined;
      });
    }
    (ctx.consents ??= {}).pending = result;
    return undefined;
  }

  /**
   * Phase 1 of MFA enrollment. Picks the method (auto-pick if only one
   * transport, otherwise pause for the picker form), handles the `skip`
   * alt-action in `'optional'` mode, and — when TOTP is picked — provisions
   * the secret idempotently in the same step body so the next iteration can
   * proceed straight to confirm. Sync-friendly return type because the
   * auto-pick branch and the picker-form branch both stay synchronous; the
   * TOTP-provisioning tail is the only async path.
   *
   * Atomic boundary: after this helper runs, `ctx.enrollMethod` is set AND
   * (for totp) `ctx.enrollSecret` is provisioned. Confirm doesn't need to
   * worry about provisioning.
   */
  protected enrollPickPhase(deps: MfaEnrollDeps): undefined | Promise<undefined> {
    const { ctx, username, users, forms, transports, issuer } = deps;
    // Ensure `enrollAvailableTransports` populated whether the caller entered
    // with no `enrollMethod` (this helper will set it) or with one already
    // chosen by a consumer setter override (e.g. `inviteSetupMfa`).
    if (!ctx.enrollAvailableTransports) {
      ctx.enrollAvailableTransports = [...transports];
    }

    // 0-transport guard — no method can be picked. Optional mode auto-skips
    // (mirrors a user `skip` click); required mode is a misconfiguration —
    // forced enrolment can't be satisfied with nothing to enrol into, and
    // rendering an empty picker would dead-end the user.
    if (transports.length === 0) {
      if (deps.mode === "optional") {
        ctx.enrollDone = true;
        deps.onComplete?.(ctx);
        return undefined;
      }
      throw new HttpError(
        500,
        "MFA enrollment is required but no transports are configured. " +
          "Override `prepareMfaSetup` to provide at least one transport, or set `mfaMode` to 'disabled'.",
      );
    }

    // Pick: auto-pick when only one transport; otherwise pause for the picker
    // form. The picker branch may short-circuit via `skip` in `'optional'` mode.
    if (transports.length === 1) {
      ctx.enrollMethod = transports[0];
    } else {
      const wf = useAtscriptWf(forms.pickMethod);
      // `'optional'` mode: the pickMethod form exposes a `skip` action. Read
      // it BEFORE `resolveInput()` so the user can decline without filling in
      // any field. A skip marks enrollment complete without persisting a
      // method — the caller's loop-exit signal flips next iteration. No
      // cleanup needed at Phase 1 — nothing has been persisted yet.
      if (deps.mode === "optional" && wf.resolveAction() === "skip") {
        ctx.enrollDone = true;
        deps.onComplete?.(ctx);
        return undefined;
      }
      const input = wf.resolveInput() as { method: string };
      const picked = input.method as MfaTransport;
      if (!ctx.enrollAvailableTransports.includes(picked)) {
        throw wf.requireInput({ errors: { method: "Unknown method" } });
      }
      ctx.enrollMethod = picked;
    }

    // Idempotent TOTP secret provisioning folded into Phase 1. Gated on
    // `!ctx.enrollSecret` so it runs exactly once per enrollment attempt —
    // re-entry after `useDifferentMethod` clears `enrollSecret` via
    // `cleanupEnrollment`, so a switch FROM totp TO totp re-provisions cleanly.
    if (ctx.enrollMethod === "totp" && !ctx.enrollSecret) {
      const secret = generateTotpSecret();
      const uri = generateTotpUri(secret, issuer, username);
      return this.withStoreErrorTranslation(() =>
        users.addMfaMethod(username, {
          name: "totp",
          value: secret,
          confirmed: false,
        }),
      ).then(() => {
        ctx.enrollSecret = secret;
        ctx.enrollUri = uri;
        return undefined;
      });
    }

    return undefined;
  }

  /**
   * Phase 2 of MFA enrollment. Collects the sms/email address, persists it as
   * an unconfirmed method, mints + dispatches the pincode. Handles `skip` /
   * `useDifferentMethod` alt-actions. Not invoked for totp (no address to
   * collect — the schema condition gates it out).
   */
  protected async enrollAddressPhase(deps: MfaEnrollDeps): Promise<undefined> {
    const { ctx, username, users, forms, pincodeLength, pincodeTtlMs, pincodeResendTimeoutMs } =
      deps;
    const wf = useAtscriptWf(forms.address);
    // Alt-actions read BEFORE `resolveInput()` so the user can skip / switch
    // method without filling the address field. At Phase 2 entry no sms/email
    // method has been persisted yet (Phase 1 only sets ctx.enrollMethod for
    // sms/email; the addMfaMethod call lives further down in this block) so
    // no cleanup is needed for either branch.
    const action = wf.resolveAction();
    if (deps.mode === "optional" && action === "skip") {
      ctx.enrollDone = true;
      deps.onComplete?.(ctx);
      return undefined;
    }
    if (action === "useDifferentMethod") {
      delete ctx.enrollMethod;
      return undefined;
    }
    const input = wf.resolveInput() as { address: string };
    const methodName = ctx.enrollMethod as MfaTransport;
    await this.withStoreErrorTranslation(() =>
      users.addMfaMethod(username, {
        name: methodName,
        value: input.address,
        confirmed: false,
      }),
    );
    ctx.enrollAddress = input.address;
    const code = this.mintPin(ctx, pincodeLength, pincodeTtlMs);
    ctx.enrollPincodeCooldown = Date.now() + pincodeResendTimeoutMs;
    await this.sendEnrollPincode(ctx, deps, input.address, code);
    return undefined;
  }

  /**
   * Phase 3 of MFA enrollment. Verifies the user-submitted code (TOTP or
   * pincode), marks the method confirmed, sets it as the default, and flags
   * `ctx.enrollDone = true`. Handles `skip` / `useDifferentMethod` / `resend`
   * alt-actions (cleanup on the first two; resend re-mints + redispatches).
   *
   * Idempotently provisions the TOTP secret at the top when missing — covers
   * the path where a consumer setter override (e.g. `inviteSetupMfa`)
   * pre-picks totp, leaving pickPhase's schema gate closed; the secret IS
   * what confirm needs, so confirm guarantees it exists. For sms/email the
   * unconfirmed method row + pincode are written by addressPhase, so there's
   * nothing to provision here.
   */
  protected async enrollConfirmPhase(deps: MfaEnrollDeps): Promise<undefined> {
    const { ctx, username, users, forms, pincodeLength, pincodeTtlMs, pincodeResendTimeoutMs } =
      deps;
    // Idempotent TOTP provisioning: gated on `!ctx.enrollSecret` so it runs
    // exactly once per enrollment attempt. Pause AFTER provisioning (returning
    // here pauses on the confirm form, which the schema then re-enters with
    // `enrollSecret` populated) so the wire payload carries the URI on first
    // pass. We DON'T eagerly call `requireInput` — the form auto-pauses by
    // resolveInput's contract on missing input.
    if (ctx.enrollMethod === "totp" && !ctx.enrollSecret) {
      const secret = generateTotpSecret();
      const uri = generateTotpUri(secret, deps.issuer, username);
      await this.withStoreErrorTranslation(() =>
        users.addMfaMethod(username, { name: "totp", value: secret, confirmed: false }),
      );
      ctx.enrollSecret = secret;
      ctx.enrollUri = uri;
      // Fall through to confirm-form pause below.
    }
    const wf = useAtscriptWf(forms.confirm);
    // Alt-actions read BEFORE `resolveInput()`. By Phase 3 the method row IS
    // persisted (Phase 1 totp / Phase 2 sms+email both call addMfaMethod
    // unconfirmed), so skip + useDifferentMethod must clean up via
    // `cleanupEnrollment` before letting the loop exit / re-enter.
    const action = wf.resolveAction();
    if (deps.mode === "optional" && action === "skip") {
      await this.cleanupEnrollment(ctx, users, username);
      ctx.enrollDone = true;
      deps.onComplete?.(ctx);
      return undefined;
    }
    if (action === "useDifferentMethod") {
      await this.cleanupEnrollment(ctx, users, username);
      return undefined;
    }
    if (action === "resend") {
      if (ctx.enrollMethod === "totp") {
        // TOTP has no pincode to resend — the secret is fixed. The form hides
        // the button for totp; this guard is defense-in-depth.
        throw wf.requireInput({ formMessage: "Resend is not applicable for TOTP" });
      }
      if (ctx.enrollPincodeCooldown && Date.now() < ctx.enrollPincodeCooldown) {
        const waitSec = Math.ceil((ctx.enrollPincodeCooldown - Date.now()) / 1000);
        throw wf.requireInput({
          formMessage: `Please wait ${waitSec}s before requesting another code`,
        });
      }
      const code = this.mintPin(ctx, pincodeLength, pincodeTtlMs);
      ctx.enrollPincodeCooldown = Date.now() + pincodeResendTimeoutMs;
      await this.sendEnrollPincode(ctx, deps, ctx.enrollAddress as string, code);
      return undefined;
    }
    const input = wf.resolveInput() as { code: string };
    if (ctx.enrollMethod === "totp") {
      try {
        await users.verifyTotpSetupCode(username, input.code);
      } catch (err) {
        if (err instanceof UserAuthError && err.type === "MFA_INVALID") {
          throw wf.requireInput({ errors: { code: "Invalid code" } });
        }
        throw err;
      }
    } else {
      const pinErr = this.verifyPin(ctx, input.code);
      if (pinErr) throw wf.requireInput({ errors: pinErr });
    }
    const methodName = ctx.enrollMethod as MfaTransport;
    await this.withStoreErrorTranslation(() => users.confirmMfaMethod(username, methodName));
    await users.setDefaultMfaMethod(username, methodName);
    ctx.enrollDone = true;
    delete ctx.pin;
    delete ctx.pinExpire;
    delete ctx.enrollPincodeCooldown;
    deps.onComplete?.(ctx);
    return undefined;
  }

  /**
   * Send a pincode for the active sms/email enrollment method and stamp
   * `ctx.pinSentTo` with the masked recipient. Shared by Phase 2 initial
   * dispatch and Phase 3 `resend`. Caller is responsible for `mintPin` +
   * stamping `enrollPincodeCooldown` BEFORE calling — this just dispatches.
   * Not called for TOTP (no pincode to send).
   */
  protected async sendEnrollPincode(
    ctx: MfaEnrollCtx,
    deps: MfaEnrollDeps,
    address: string,
    code: string,
  ): Promise<void> {
    if (ctx.enrollMethod === "email") {
      ctx.pinSentTo = maskEmail(address);
      await deps.deliver({
        channel: "email",
        kind: "login.pincode",
        recipient: address,
        code,
        expiresAt: ctx.pinExpire as number,
        userId: deps.username,
      });
    } else {
      ctx.pinSentTo = maskPhone(address);
      await deps.deliver({
        channel: "sms",
        kind: "login.pincode",
        recipient: address,
        code,
        ttlMs: deps.pincodeTtlMs,
        userId: deps.username,
      });
    }
  }

  /**
   * Cleanup any partially-persisted enrollment state (unconfirmed method row +
   * ctx scratch). Called when the user picks `skip` or `useDifferentMethod`
   * mid-flow on Phase 3, where the unconfirmed method has already been written
   * via `addMfaMethod` (Phase 1 for totp, Phase 2 for sms/email). On
   * `useDifferentMethod` the caller relies on `enrollMethod` being cleared so
   * the loop re-enters Phase 1.
   */
  protected async cleanupEnrollment(
    ctx: MfaEnrollCtx,
    users: UserService,
    username: string,
  ): Promise<void> {
    if (ctx.enrollMethod) {
      await this.withStoreErrorTranslation(() =>
        users.removeMfaMethod(username, ctx.enrollMethod!),
      );
    }
    delete ctx.enrollMethod;
    delete ctx.enrollAddress;
    delete ctx.enrollSecret;
    delete ctx.enrollUri;
    delete ctx.pin;
    delete ctx.pinExpire;
    delete ctx.pinSentTo;
    delete ctx.enrollPincodeCooldown;
  }
}

// ── Shared @Workflow schema fragments ──
//
// Composable schema arrays shared across the bundled auth workflows. Each
// fragment is typed against `AuthWfCtxBase` so condition functions inside
// only read canonical group fields (e.g. `ctx.consents?.persisted`), not
// per-workflow flat aliases — keeps fragments portable across the three
// WF ctx interfaces and ready for the B1.4 flat-alias drop.
//
// Each WF's `@WorkflowSchema<<WfCtx>>([...])` spreads these in place; the
// `TWorkflowItem<T>` type is contravariant in `T` (condition fns take `T`
// as a parameter), so under `strictFunctionTypes` a `TWorkflowItem<AuthWfCtxBase>`
// IS assignable to `TWorkflowItem<LoginWfCtx>` etc.

/**
 * `prepare-consents` schema entry — fires once per workflow run, after the
 * `!ctx.username` break, to populate `ctx.consents.pending` from
 * `ConsentStore.getPendingConsents()`. Shared by `LoginWorkflow`,
 * `InviteWorkflow`, and `RecoveryWorkflow`.
 */
export const consentsPreludeSchema: TWorkflowSchema<AuthWfCtxBase> = [{ id: "prepare-consents" }];

/**
 * `persist-consents` schema entry — batched consent persistence. Fires once
 * per workflow run after any carrier form collected `consents` via
 * `processInlineConsent` (which sets `ctx.consents.decidedAt`). The
 * `decidedAt` timestamp is the single capture-source gate;
 * `!persisted` AND-s for single-fire idempotency.
 */
export const consentsPersistTailSchema: TWorkflowSchema<AuthWfCtxBase> = [
  {
    id: "persist-consents",
    condition: (ctx) => !!ctx.consents?.decidedAt && !ctx.consents?.persisted,
  },
];

/**
 * `prepare-password-rules` + `create-password-form` pair — populates
 * `ctx.password.policies` (the `TransferablePolicy[]` wire shape) then
 * pauses on `SetPasswordForm`. Used by `LoginWorkflow` for the forced
 * password-change phase; the surrounding subflow (forced-initial /
 * expired) supplies the outer gate. `RecoveryWorkflow` uses a different
 * shape (`set-password` step, no `create-password-form`) and does not
 * consume this fragment. `InviteWorkflow` splits the pair with
 * `consentsPreludeSchema` between the two entries and gates
 * `create-password-form` on its own `ctx.passwordSet` flat alias, so
 * it cannot adopt this fragment without reordering — left inline there.
 */
export const passwordChangeSchema: TWorkflowSchema<AuthWfCtxBase> = [
  { id: "prepare-password-rules" },
  { id: "create-password-form" },
];
