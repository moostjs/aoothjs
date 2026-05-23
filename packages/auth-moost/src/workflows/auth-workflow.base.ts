/**
 * Shared helpers for the three bundled auth workflows
 * (`LoginWorkflow` / `InviteWorkflow` / `RecoveryWorkflow`). Holds the
 * auth-specific glue (`requireUsername`, `translatePasswordSetError`),
 * the pincode primitives (`mintPin`, `verifyPin`), and the HTTP-context
 * `resolveClientIp()` reader. Workflows extend this class and call helpers
 * via `this.<name>(...)`.
 */
import { UserAuthError } from "@aooth/user";
import { HttpError } from "@moostjs/event-http";
import { useRequest } from "@wooksjs/event-http";

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
}
