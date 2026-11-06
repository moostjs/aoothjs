import { tryGetCurrent, useLocale } from "@wooksjs/event-core";
import { formatMessage, registerMessages, useTranslate } from "moost";

/**
 * Code-keyed catalogue of every user-facing text `AuthWorkflow` produces —
 * form errors, banners, finish envelopes and button labels. Templates are
 * English; `{name}` placeholders are filled from the message params.
 *
 * Registered with moost's `registerMessages` on import, so a moost translator
 * (`setTranslator`) translates every code and `$i18n` serves the templates.
 * Override per app with `AuthWorkflowOpts.messages` (a partial map, or a
 * function that receives the code and params and returns the text), or
 * override `AuthWorkflow.msg()`.
 */
export const AOOTH_MESSAGES = {
  // ── Sign-in ──
  INVALID_CREDENTIALS: "Invalid credentials",
  AOOTH_ACCOUNT_LOCKED: "Account locked, please try again later",
  INVALID_PASSWORD: "Invalid password",
  INCORRECT_PASSWORD: "Incorrect password",
  SESSION_LIMIT_REACHED: "Session limit reached",
  PASSWORD_CHANGED_SIGN_IN_AGAIN: "Your password was changed. Please sign in again.",

  // ── Codes (MFA / OTP) ──
  AOOTH_INVALID_CODE: "Invalid code",
  AOOTH_CODE_EXPIRED: "Code expired",
  AOOTH_TOO_MANY_CODE_ATTEMPTS: "Too many invalid attempts. Please request a new code.",
  /** Params: `seconds`. */
  AOOTH_RESEND_WAIT: "Please wait {seconds}s before requesting a new code.",
  /** Params: `seconds`. */
  AOOTH_RESEND_WAIT_ANOTHER: "Please wait {seconds}s before requesting another code",
  /** Params: `seconds`, `channel` (`SMS` / `email`). */
  AOOTH_RESEND_WAIT_CHANNEL: "Please wait {seconds}s before requesting another {channel} code",
  TOTP_RESEND_NOT_APPLICABLE: "Resend is not applicable for TOTP",
  /** HTTP 400 — a TOTP code submitted for an account without TOTP. */
  TOTP_NOT_CONFIGURED: "No TOTP MFA configured",

  // ── Contact addresses (MFA / channel enrolment) ──
  AOOTH_ADDRESS_REQUIRED: "This field is required",
  AOOTH_INVALID_EMAIL_ADDRESS: "Enter a valid email address",
  AOOTH_INVALID_PHONE_NUMBER: "Enter a valid phone number",
  OTP_DISCLOSURE_EMAIL:
    "By providing your email address, you consent to receive one-time security codes from us via email. Standard email delivery may apply.",
  OTP_DISCLOSURE_PHONE:
    "By providing your phone number, you consent to receive one-time security codes from us via SMS. Message and data rates may apply.",

  // ── MFA management ──
  UNKNOWN_MFA_METHOD: "Unknown MFA method",
  AOOTH_UNKNOWN_METHOD: "Unknown method",
  AOOTH_METHOD_UNAVAILABLE: "That method isn't available",
  AOOTH_METHOD_NOT_CHANGEABLE: "That method can't be changed here.",
  KEEP_ONE_MFA_METHOD: "You must keep at least one two-factor method.",
  AOOTH_CHOOSE_OPTION: "Choose an option",
  ALL_MFA_METHODS_SET_UP: "You've already set up every available authentication method.",
  NO_MFA_CHANGES: "No changes were made to your two-factor methods.",
  LAST_MFA_METHOD_NOT_REMOVABLE:
    "You must keep at least one two-factor method, so this one can't be removed.",
  MFA_METHOD_TOTP: "Authenticator app",
  MFA_METHOD_EMAIL: "Email code",
  MFA_METHOD_SMS: "Text-message code",
  /** Params: `method` (the method's label). */
  MFA_METHOD_ADDED: "{method} added.",
  /** Params: `method`. */
  MFA_METHOD_UPDATED: "{method} updated.",
  /** Params: `method`. */
  MFA_METHOD_REMOVED: "{method} removed.",

  // ── Passwords ──
  PASSWORDS_DO_NOT_MATCH: "Passwords do not match",
  PASSWORD_CHANGE_TOO_RECENT: "You changed your password too recently. Please try again later.",
  PASSWORD_CHANGED: "Your password has been changed.",
  PASSWORD_UPDATED_REDIRECTING: "Password updated. Redirecting to sign-in…",
  PASSWORD_UPDATED_STILL_LOCKED:
    "Password updated, but your account is still locked. Contact an administrator to regain access.",

  // ── Password screens (heading + intro) ──
  CHANGE_PASSWORD_HEADING: "Change your password",
  CHANGE_PASSWORD_INTRO: "Enter your current password, then choose a new one.",
  SET_PASSWORD_EXPIRED_HEADING: "Your password has expired",
  SET_PASSWORD_EXPIRED_INTRO:
    "Choose a new password to continue. The previous one is no longer valid.",
  SET_PASSWORD_RESET_HEADING: "Reset your password",
  SET_PASSWORD_RESET_INTRO: "Choose a new password for your account.",
  SET_PASSWORD_INVITE_HEADING: "Welcome — set your password",
  SET_PASSWORD_INVITE_INTRO: "Choose a password to activate your account.",
  SET_PASSWORD_INITIAL_HEADING: "Set your initial password",
  SET_PASSWORD_INITIAL_INTRO:
    "Your account was created without a password. Choose one to continue.",

  // ── Recovery / signup ──
  /** A magic link that cannot be used: expired, of another purpose, or already used up. */
  AOOTH_MAGIC_LINK_INVALID: "This link is invalid or has expired. Please request a new one.",
  SIGNUP_DISABLED: "Self-signup is currently disabled.",
  AOOTH_ALREADY_HAVE_ACCOUNT: "You already have an account. Please sign in.",
  AOOTH_ACCOUNT_LINKED: "Account linked.",
  /** HTTP 400 — the SSO alt action named a provider that is not offered. */
  UNKNOWN_SSO_PROVIDER: "Unknown SSO provider",

  // ── Invites ──
  AOOTH_ACCOUNT_CREATED: "Your account has been created.",
  AOOTH_INVALID_ROLE: "Invalid role",
  INVITE_ALREADY_PENDING: "Invite already pending",
  AOOTH_USER_ALREADY_EXISTS: "User already exists",
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
  AOOTH_BACK: "Back",
  AOOTH_GO_NOW: "Go now",
} as const;

registerMessages(AOOTH_MESSAGES);

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
export function renderAoothMessage(template: string, params?: AoothMessageParams): string {
  return formatMessage(template, params);
}

/**
 * Resolve `code`: `messages` (the app's override, when given), then moost's
 * translator in the current event's locale (`useTranslate`), then the English
 * template. Outside an event the translator is skipped.
 */
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
  return translateCode(code, params, renderAoothMessage(AOOTH_MESSAGES[code], params));
}

/** The current event's locale (`useLocale()`); `undefined` outside an event. */
export function currentLocale(): string | undefined {
  const event = tryGetCurrent();
  return event ? useLocale(event).get() : undefined;
}

/**
 * `code` through moost's translator in the current event's locale, else
 * `english` (the filled English text). Outside an event: `english`.
 */
export function translateCode(
  code: string,
  params: Readonly<Record<string, unknown>> | undefined,
  english: string,
): string {
  const event = tryGetCurrent();
  return event ? useTranslate(event)(code, params, english) : english;
}
