/**
 * Shared helpers for the three bundled auth workflows
 * (`LoginWorkflow` / `InviteWorkflow` / `RecoveryWorkflow`). Holds the
 * auth-specific glue (`requireUsername`, `translatePasswordSetError`),
 * the pincode primitives (`mintPin`, `verifyPin`), and the HTTP-context
 * `resolveClientIp()` reader. Workflows extend this class and call helpers
 * via `this.<name>(...)`.
 */
import {
  generateTotpSecret,
  generateTotpUri,
  maskEmail,
  maskPhone,
  UserAuthError,
  type UserService,
} from "@aooth/user";
import { useAtscriptWf } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { useRequest } from "@wooksjs/event-http";

/**
 * Method names for the MFA enrollment helper. Re-exported from
 * `login.workflow.options` as `MfaTransport` (kept as the public alias) so
 * existing consumers don't need to switch import paths.
 */
export type MfaTransport = "sms" | "email" | "totp";

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
  "backupCodes",
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
 * relevant subset of `LoginWfCtx` so the helper stays workflow-agnostic —
 * `InviteWfCtx` / `RecoveryWfCtx` can pass through compatibly (or, when they
 * don't carry `acceptance`, the gates skip every check).
 */
export interface InlineConsentCtx {
  acceptance?: {
    termsVersion?: string;
    consentMarketing: boolean;
  };
  termsAcceptedVersion?: string;
  termsAcceptedDone?: boolean;
  termsAcceptedAt?: number;
  marketingDecidedAt?: number;
  consentsPersisted?: boolean;
  pendingMarketingOptIn?: boolean;
}

/**
 * Subset of the input payload that `processInlineConsent` reads. The
 * accepted terms VERSION is NOT collected from the client — the server
 * reads its own `ctx.acceptance.termsVersion` instead. See the helper's
 * security comment for rationale.
 */
export interface InlineConsentInput {
  acceptedTerms?: boolean;
  marketingOptIn?: boolean;
}

/**
 * Consent event emitted to the `ConsentStore.save(username, events)` DI
 * provider. Storage shape is intentionally the consumer's call — Mongo users
 * typically push the events onto an embedded array, SQL users insert into an
 * audit table, event-bus users publish to a topic. The library batches all
 * collected events from a single workflow run into one call.
 */
export interface ConsentEvent {
  kind: "terms" | "marketing" | (string & {});
  version?: string;
  optIn?: boolean;
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

export class AuthWorkflowBase {
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
   * Translate password-mutation errors from `UserService.setPassword` /
   * `createUser` into the matching HTTP status. All `UserAuthError` shapes from
   * a set-password call are client-side (policy / history / mismatch), so they
   * collapse to 400.
   */
  protected translatePasswordSetError(err: unknown): never {
    if (err instanceof UserAuthError) throw new HttpError(400, err.message);
    throw err;
  }

  /**
   * Wrap an `UserStore` mutation that can race (`withCas`-backed paths:
   * `consumeBackupCode`, `addMfaMethod`, `confirmMfaMethod`, `addTrustedDevice`)
   * so a CAS retry-budget exhaustion surfaces as 409 Conflict — the canonical
   * OCC status — rather than bubbling to the moost default 500. Client SHOULD
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
   * SECURITY GATE: only processes the consent fields when the matching
   * `acceptance` policy is active AND the value hasn't already been captured
   * for this workflow run. If `ctx.termsAcceptedDone === true` OR
   * `ctx.acceptance?.termsVersion` is unset, the server SILENTLY IGNORES
   * `input.acceptedTerms` even when the payload contains it. Same gate for
   * `marketingOptIn` — once `ctx.consentsPersisted === true`, subsequent
   * payloads cannot flip the value. This is the load-bearing defense
   * against an attacker submitting falsified hidden-field values to withdraw
   * consent or flip a marketing opt-in.
   *
   * The accepted-terms VERSION is NOT collected from the client. The server
   * is the authoritative source of truth — when `acceptedTerms: true`
   * arrives and the gate is open, `ctx.termsAcceptedVersion` is set
   * directly from `ctx.acceptance.termsVersion`. Rationale:
   *   (a) No client round-trip means no surface for a tampered version
   *       (an attacker cannot record acceptance of a stale or fabricated
   *       version — the server writes its own current version regardless).
   *   (b) `@atscript/vue-form` ships no `hidden` component renderer, so a
   *       `@ui.form.type 'hidden'` field would break every SPA-rendered
   *       carrier form extending `WithInlineConsentForm`.
   *
   * Terms are validated + stashed inline (workflow proceeds only when the
   * checkbox is ticked). Marketing is stashed only — the async user-store
   * write defers to the `persist-consents` step which fires once
   * `ctx.username` is set.
   */
  protected processInlineConsent(
    ctx: InlineConsentCtx,
    input: InlineConsentInput,
    wf: WfRequireInputOnly,
  ): void {
    if (ctx.acceptance?.termsVersion && !ctx.termsAcceptedDone) {
      if (!input.acceptedTerms) {
        throw wf.requireInput({ errors: { acceptedTerms: "You must accept the terms" } });
      }
      // Server is authoritative — record OUR current version, not anything
      // submitted by the client.
      ctx.termsAcceptedVersion = ctx.acceptance.termsVersion;
      ctx.termsAcceptedDone = true;
      ctx.termsAcceptedAt = Date.now();
    }
    if (
      ctx.acceptance?.consentMarketing &&
      !ctx.consentsPersisted &&
      input.marketingOptIn !== undefined
    ) {
      ctx.pendingMarketingOptIn = Boolean(input.marketingOptIn);
      ctx.marketingDecidedAt = Date.now();
    }
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
