/**
 * Named workflow-option presets selected per-request via the `x-wf-variant`
 * HTTP header. Playwright sets the header on each `<AsWfForm>` trigger so the
 * single backend can serve every variant in `USER_STORIES.md` §3/4/5 without
 * spinning a fresh process per profile.
 *
 * The maps below are `Partial<...Opts>` because the demo's `mergeWfOpts`
 * two-level deep merge layers them on top of `demoLoginOpts` /
 * `demoRecoveryOpts` / `demoInviteOpts` — each entry only carries the fields
 * that meaningfully shape its profile.
 */
import type {
  InviteWorkflowOpts,
  LoginWorkflowOpts,
  RecoveryWorkflowOpts,
} from "@aooth/auth-moost";
import { useHeaders } from "@wooksjs/event-http";

/**
 * Login profiles — keys mirror `USER_STORIES.md` §3 variants L-A…L-J plus the
 * dedicated `redirect-home` row used by WF-LOGIN-031.
 */
export const LOGIN_VARIANTS: Record<string, Partial<LoginWorkflowOpts>> = {
  minimal: {
    mfa: { enabled: false },
    alternateCredentials: { forgotPassword: true },
  },
  "mfa-totp": {
    mfa: { enabled: true, transports: ["totp"], backupCodes: true },
  },
  "mfa-full": {
    mfa: { enabled: true, transports: ["sms", "email", "totp"], backupCodes: true },
  },
  enrollment: {
    enrollment: { ensureEmail: true, ensurePhone: true },
    mfa: { enabled: true, transports: ["email", "sms", "totp"] },
  },
  "device-trust": {
    deviceTrust: { enabled: true, optIn: true, skipsMfa: true },
    mfa: { enabled: true, transports: ["totp"] },
  },
  guards: {
    guards: { passwordInitial: true, emailVerifiedRequired: true },
    mfa: { enabled: false },
  },
  acceptance: {
    acceptance: {
      termsVersion: "v1",
      profileCompleteRequired: true,
      consentMarketing: true,
    },
  },
  "multi-context": {
    multiContext: { tenantSelect: true, personaSelect: true },
  },
  concurrency: {
    sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "kickPrompt" } },
  },
  full: {
    alternateCredentials: { forgotPassword: true, signup: true, magicLink: true },
    guards: { passwordInitial: true, emailVerifiedRequired: true, passwordExpiry: true },
    enrollment: { ensureEmail: true, ensurePhone: true },
    mfa: { enabled: true, transports: ["sms", "email", "totp"], backupCodes: true },
    deviceTrust: { enabled: true, optIn: true, skipsMfa: true },
    acceptance: {
      termsVersion: "v1",
      profileCompleteRequired: true,
      consentMarketing: true,
    },
    multiContext: { tenantSelect: true, personaSelect: true },
    sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "kickPrompt" } },
  },
  "redirect-home": {
    finalize: { redirect: "home" },
  },
};

/**
 * Recovery profiles — keys mirror `USER_STORIES.md` §4 variants R-A…R-G.
 */
export const RECOVERY_VARIANTS: Record<string, Partial<RecoveryWorkflowOpts>> = {
  "default-magiclink": {
    delivery: { mode: "magicLink" },
  },
  "otp-email": {
    delivery: { mode: "otp", otp: { transports: ["email"] } },
  },
  "otp-sms": {
    delivery: { mode: "otp", otp: { transports: ["sms"] } },
  },
  "otp-both": {
    delivery: { mode: "otp", otp: { transports: ["email", "sms"] } },
  },
  choice: {
    delivery: { mode: "choice" },
  },
  "pre-factor": {
    preReset: { requireKnownFactor: true },
  },
  "fresh-login": {
    postReset: { freshLoginRequired: true, revokeAllSessions: true },
  },
};

/**
 * Invite profiles — keys mirror `USER_STORIES.md` §5 variants I-A…I-G.
 */
export const INVITE_VARIANTS: Record<string, Partial<InviteWorkflowOpts>> = {
  "email-no-roles": {
    adminForm: { collectRoles: false },
    send: { mode: "email" },
  },
  "roles-profile": {
    adminForm: { collectRoles: true },
    send: { mode: "email" },
  },
  "shareable-link": {
    send: { mode: "shareableLink" },
  },
  "choice-freshlogin": {
    send: { mode: "choice" },
    accept: { freshLoginRequired: true },
  },
  "audit-enabled": {
    audit: { enabled: true },
  },
  "cancellation-disabled": {
    cancellation: { allowed: false },
  },
  "short-ttl-confirmation": {
    send: { tokenTtlMs: 1000 },
    accept: { showConfirmation: true },
  },
};

/**
 * Look up a variant preset by name. Returns `undefined` when `name` is missing
 * or not registered — the caller falls back to the bare demo opts. Silent on
 * miss by design: Playwright sets the header explicitly per spec, and a
 * mistyped variant should not log-spam the dev server.
 */
export function pickVariant<T>(
  map: Record<string, Partial<T>>,
  name: string | null | undefined,
): Partial<T> | undefined {
  if (!name) return undefined;
  return Object.prototype.hasOwnProperty.call(map, name) ? map[name] : undefined;
}

/**
 * Reads the `x-wf-variant` request header. Wrapped in try/catch because the
 * workflow subclass constructors that call this also run during moost's
 * non-HTTP DI resolution phase, where `useHeaders()` throws.
 */
export function readVariantHeader(): string | null {
  try {
    const raw = useHeaders()["x-wf-variant"];
    if (typeof raw === "string") return raw;
    if (Array.isArray(raw) && typeof raw[0] === "string") return raw[0];
    return null;
  } catch {
    return null;
  }
}
