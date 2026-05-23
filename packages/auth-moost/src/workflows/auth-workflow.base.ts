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
 * Context shape consumed by `runMfaEnrollment`. Both `LoginWfCtx` and
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
  /** TOTP provisioning issuer (rendered in the authenticator app). */
  issuer: string;
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
   * Shared 3-phase MFA enrollment driver — pick method, collect address (or
   * provision TOTP secret), confirm code. Used by both
   * `LoginWorkflow.mfa-enroll-required` (forced enrollment when policy tightens
   * for an existing user) and `InviteWorkflow.inviteEnrollMfa*` (forced
   * enrollment during the accept tail when policy demands MFA at activation
   * time). The step body in each workflow delegates here; `@Step` decorators
   * must stay on the concrete class (moost requirement).
   *
   * Sets `deps.ctx.enrollDone = true` when the 3 phases complete. Callers gate
   * their step on `!ctx.enrollDone` and translate that into their own
   * loop-exit signal (login: `mfaChecked = true`; invite: `enrollDone` directly).
   */
  protected async runMfaEnrollment(deps: MfaEnrollDeps): Promise<void> {
    const {
      ctx,
      username,
      users,
      deliver,
      forms,
      transports,
      pincodeLength,
      pincodeTtlMs,
      issuer,
    } = deps;

    // Phase 1: pick method. For TOTP also provision + persist the secret
    // immediately so the confirm step can render the QR.
    if (!ctx.enrollMethod) {
      if (!ctx.enrollAvailableTransports) {
        ctx.enrollAvailableTransports = [...transports];
      }
      const wf = useAtscriptWf(forms.pickMethod);
      const input = wf.resolveInput() as { method: string };
      const picked = input.method as MfaTransport;
      if (!ctx.enrollAvailableTransports.includes(picked)) {
        throw wf.requireInput({ errors: { method: "Unknown method" } });
      }
      ctx.enrollMethod = picked;
      if (picked === "totp") {
        const secret = generateTotpSecret();
        const uri = generateTotpUri(secret, issuer, username);
        await this.withStoreErrorTranslation(() =>
          users.addMfaMethod(username, {
            name: "totp",
            value: secret,
            confirmed: false,
          }),
        );
        ctx.enrollSecret = secret;
        ctx.enrollUri = uri;
      }
      return;
    }

    // Phase 2: collect address + send pincode (sms/email only).
    if ((ctx.enrollMethod === "sms" || ctx.enrollMethod === "email") && !ctx.enrollAddress) {
      const wf = useAtscriptWf(forms.address);
      const input = wf.resolveInput() as { address: string };
      const methodName = ctx.enrollMethod;
      await this.withStoreErrorTranslation(() =>
        users.addMfaMethod(username, {
          name: methodName,
          value: input.address,
          confirmed: false,
        }),
      );
      ctx.enrollAddress = input.address;
      const code = this.mintPin(ctx, pincodeLength, pincodeTtlMs);
      if (methodName === "email") {
        ctx.pinSentTo = maskEmail(input.address);
        await deliver({
          channel: "email",
          kind: "login.pincode",
          recipient: input.address,
          code,
          expiresAt: ctx.pinExpire as number,
          userId: username,
        });
      } else {
        ctx.pinSentTo = maskPhone(input.address);
        await deliver({
          channel: "sms",
          kind: "login.pincode",
          recipient: input.address,
          code,
          ttlMs: pincodeTtlMs,
          userId: username,
        });
      }
      return;
    }

    // Phase 3: confirm.
    const wf = useAtscriptWf(forms.confirm);
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
  }
}
