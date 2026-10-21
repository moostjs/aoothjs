/**
 * Code-keyed catalogue of every user-facing text `AuthWorkflow` produces —
 * form errors, banners, finish envelopes and button labels. Templates are
 * English; `{name}` placeholders are filled from the message params.
 *
 * Override per app with `AuthWorkflowOpts.messages` (a partial map, or a
 * function that receives the code and params and returns the text — e.g. a
 * lookup in your own i18n library), or override `AuthWorkflow.msg()`.
 */
export const AOOTH_MESSAGES = {
  // ── Sign-in ──
  INVALID_CREDENTIALS: "Invalid credentials",
  ACCOUNT_LOCKED: "Account locked, please try again later",
  INVALID_PASSWORD: "Invalid password",
  INCORRECT_PASSWORD: "Incorrect password",
  SESSION_LIMIT_REACHED: "Session limit reached",

  // ── Codes (MFA / OTP) ──
  INVALID_CODE: "Invalid code",
  /** Params: `seconds`. */
  RESEND_WAIT: "Please wait {seconds}s before requesting a new code.",
  /** Params: `seconds`. */
  RESEND_WAIT_ANOTHER: "Please wait {seconds}s before requesting another code",
  /** Params: `seconds`, `channel` (`SMS` / `email`). */
  RESEND_WAIT_CHANNEL: "Please wait {seconds}s before requesting another {channel} code",
  TOTP_RESEND_NOT_APPLICABLE: "Resend is not applicable for TOTP",

  // ── MFA management ──
  UNKNOWN_MFA_METHOD: "Unknown MFA method",
  UNKNOWN_METHOD: "Unknown method",
  METHOD_UNAVAILABLE: "That method isn't available",
  METHOD_NOT_CHANGEABLE: "That method can't be changed here.",
  KEEP_ONE_MFA_METHOD: "You must keep at least one two-factor method.",
  CHOOSE_OPTION: "Choose an option",
  ALL_MFA_METHODS_SET_UP: "You've already set up every available authentication method.",
  NO_MFA_CHANGES: "No changes were made to your two-factor methods.",

  // ── Passwords ──
  PASSWORDS_DO_NOT_MATCH: "Passwords do not match",
  PASSWORD_CHANGE_TOO_RECENT: "You changed your password too recently. Please try again later.",
  PASSWORD_CHANGED: "Your password has been changed.",
  PASSWORD_UPDATED_REDIRECTING: "Password updated. Redirecting to sign-in…",
  PASSWORD_UPDATED_STILL_LOCKED:
    "Password updated, but your account is still locked. Contact an administrator to regain access.",

  // ── Recovery / signup ──
  RECOVERY_INSTRUCTIONS_SENT: "If an account exists, you will receive instructions.",
  SIGNUP_DISABLED: "Self-signup is currently disabled.",
  ALREADY_HAVE_ACCOUNT: "You already have an account. Please sign in.",
  ACCOUNT_LINKED: "Account linked.",

  // ── Invites ──
  INVALID_ROLE: "Invalid role",
  INVITE_ALREADY_PENDING: "Invite already pending",
  USER_ALREADY_EXISTS: "User already exists",
  DUPLICATE_INVITE_REJECTED: "Duplicate invite rejected",
  INVITE_CANCELLED: "This invite has been cancelled",
  INVITE_REPLACED: "This invite was replaced by a newer one",
  INVITE_ALREADY_ACCEPTED: "This invite was already accepted.",
  CHOOSE_USERNAME_TAKEN: "This username is taken",
  USERNAME_NOT_ALLOWED: "This username is not allowed",

  // ── Authorization server ──
  AUTHZ_EXPIRED: "Authorization request expired. Please try again.",
  AUTHZ_BROWSER_MISMATCH:
    "This authorization could not be verified for your browser. Please start again.",
  AUTHZ_FAILED: "Authorization could not be completed. Please start again.",

  // ── Button labels ──
  GO_TO_SIGN_IN: "Go to sign-in",
  BACK_TO_SIGN_IN: "Back to sign-in",
  REQUEST_NEW_INVITE: "Request a new invite",
  BACK: "Back",
  GO_NOW: "Go now",
} as const;

/** A message code of {@link AOOTH_MESSAGES}. */
export type AoothMessageCode = keyof typeof AOOTH_MESSAGES;

/** Values filled into a message template's `{name}` placeholders. */
export type AoothMessageParams = Readonly<Record<string, string | number>>;

/**
 * App overrides for {@link AOOTH_MESSAGES}: a partial map (templates may use
 * the same `{name}` placeholders), or a resolver returning the final text —
 * `undefined` falls back to the built-in English template.
 */
export type AoothMessages =
  | Partial<Record<AoothMessageCode, string>>
  | ((code: AoothMessageCode, params: AoothMessageParams) => string | undefined);

/** Fill `{name}` placeholders from `params`; unknown placeholders are kept. */
export function renderAoothMessage(template: string, params: AoothMessageParams = {}): string {
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole,
  );
}

/** Resolve `code` through `messages` (when given), falling back to the English template. */
export function resolveAoothMessage(
  code: AoothMessageCode,
  params: AoothMessageParams = {},
  messages?: AoothMessages,
): string {
  if (typeof messages === "function") {
    const text = messages(code, params);
    if (text !== undefined) return text;
  } else if (messages?.[code] !== undefined) {
    return renderAoothMessage(messages[code], params);
  }
  return renderAoothMessage(AOOTH_MESSAGES[code], params);
}
