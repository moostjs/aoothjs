/**
 * Full shape per `WF_RECOVERY.md` §"`RecoveryWorkflowOptions` — full shape".
 *
 * Defaults give a one-step magic-link recovery flow (matching the pre-BIG-3.2
 * 3-step behaviour) and require the consumer to opt into OTP delivery, the
 * pre-reset factor check, fresh-login redirect, etc.
 */
import { Injectable } from "moost";

/** Magic-link TTL — also kept on the legacy `recoveryTokenTtlMs` alias below. */
export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;

export type RecoveryDeliveryMode = "magicLink" | "otp" | "choice";
export type RecoveryOtpTransport = "sms" | "email";

@Injectable()
export class RecoveryWorkflowOptions {
  // ── Delivery mode ────────────────────────────────────────────────────────
  /**
   * `'magicLink'` (default) → today's "click the link in the email" flow.
   * `'otp'` → send a numeric code on email/SMS and verify it in-band.
   * `'choice'` → adds a `selectMode` step so the user picks per-attempt.
   */
  deliveryMode: RecoveryDeliveryMode = "magicLink";

  // ── OTP transports (when deliveryMode includes OTP) ──────────────────────
  /**
   * Ordered transport list — first entry is the default unless
   * `useDifferentTransport` is invoked on the `checkOtp` step.
   */
  otpTransports: RecoveryOtpTransport[] = ["email"];
  otpCodeLength = 6;
  otpTtlMs = 5 * 60_000;
  otpResendCooldownMs = 60_000;

  // ── Magic-link (when deliveryMode includes magicLink) ────────────────────
  magicLinkTtlMs = DEFAULT_RECOVERY_TOKEN_TTL_MS;
  /**
   * Backwards-compat alias for `magicLinkTtlMs`. The e2e demo + several tests
   * still pass `recoveryTokenTtlMs` explicitly; the constructor `Object.assign`
   * propagates either field. Treated as the source of truth when set so the
   * single value drives both the magic-link TTL and the persisted state TTL.
   */
  recoveryTokenTtlMs: number = DEFAULT_RECOVERY_TOKEN_TTL_MS;

  // ── Email-to-userId mapping (moved from MoostAuthWorkflowConfig) ─────────
  /**
   * Resolves the recovery-step `email` input to the `username` (user-id) that
   * `UserService.getUser` expects. Apps whose user model separates `username`
   * from `email` MUST provide this; otherwise the workflow treats the email as
   * the username (silently missing users whose `username !== email`). Return
   * `null` when no user matches.
   */
  emailToUserId?: (email: string) => Promise<string | null> | string | null;
  /**
   * JSON-safe presence flag populated by the workflow's `snapshotOpts` so
   * schema `condition` predicates can gate on the presence of `emailToUserId`
   * without holding a non-serialisable callback in `ctx.opts`. Consumers do
   * not set this directly.
   */
  emailToUserIdEnabled?: boolean;

  // ── Rate limiting ────────────────────────────────────────────────────────
  /**
   * Default: max 2 recovery requests per email per 24h. Set to `null` to
   * disable rate-limiting entirely. When non-null, a `WorkflowRateLimitStore`
   * MUST be registered against `WORKFLOW_RATE_LIMIT_STORE_TOKEN` — the
   * workflow constructor fails loud if it is not.
   */
  rateLimit: { count: number; windowMs: number } | null = {
    count: 2,
    windowMs: 24 * 60 * 60_000,
  };

  // ── Pre-reset security gate (optional) ───────────────────────────────────
  /**
   * When `true`, after the link/OTP is verified, prompt for an additional
   * factor (phone last-4 or current TOTP). Increases friction; recommended
   * for high-security apps.
   */
  requireKnownRecoveryFactor = false;

  // ── Post-reset behavior ──────────────────────────────────────────────────
  /**
   * On by default — recovery implies "I lost control"; kick all existing
   * sessions for this user by calling `AuthCredential.revokeAllForUser`.
   */
  revokeAllSessions = true;

  /**
   * On by default — after successful reset, DO NOT auto-issue tokens;
   * redirect the user to the login page to sign in fresh with the new
   * password. Set `false` to keep the today's auto-login behavior.
   */
  freshLoginRequired = true;

  /** Redirect target when `freshLoginRequired` or `backToLogin` alt-action fires. */
  loginUrl = "/login";

  // ── Alt actions ──────────────────────────────────────────────────────────
  /** Surfaces a "back to login" alt-action on every form-bearing step. */
  backToLoginAction = true;

  // ── Audit ────────────────────────────────────────────────────────────────
  /**
   * Emits `recovery.requested` (always, even on unknown email) and
   * `recovery.completed` (only on successful reset) via the registered
   * `AuditEmitter`. No-op when no emitter is wired.
   */
  auditEvents = true;

  constructor(opts: Partial<RecoveryWorkflowOptions> = {}) {
    Object.assign(this, opts);
    // Keep magicLinkTtlMs + recoveryTokenTtlMs in sync — whichever the
    // consumer set wins; both end up identical so downstream code (the email
    // outlet's `recoveryTokenTtlMs` fallback + the `sendMagicLink` step's
    // `magicLinkTtlMs` lookup) sees one number.
    if (opts.recoveryTokenTtlMs !== undefined && opts.magicLinkTtlMs === undefined) {
      this.magicLinkTtlMs = opts.recoveryTokenTtlMs;
    } else if (opts.magicLinkTtlMs !== undefined && opts.recoveryTokenTtlMs === undefined) {
      this.recoveryTokenTtlMs = opts.magicLinkTtlMs;
    }
  }
}
