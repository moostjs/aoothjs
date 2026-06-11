/**
 * Discriminator for auth-related email events emitted by the workflow stack.
 *
 * `mfa.code` is reserved for v2 — v1 is TOTP only. `login.pincode`,
 * `recovery.pincode`, `invite.pincode` and `notifyNewDevice` are added with
 * BIG 3.1 (login workflow re-implementation). `securityAlert` is the
 * consumer-triggered security notice (e.g. impossible-travel from a
 * `resolveRiskStepUp` override) — never auto-sent by the framework.
 */
export type AuthEmailKind =
  | "recovery.magicLink"
  | "invite.magicLink"
  | "mfa.code"
  | "login.pincode"
  | "recovery.pincode"
  | "invite.pincode"
  | "notifyNewDevice"
  | "securityAlert";

/**
 * Structured event passed to `EmailSender.send()` from inside the auth
 * workflows. Flat and serialisable so consumers can route it to any
 * transport (templated mailer, queue, webhook).
 */
export interface AuthEmailEvent {
  kind: AuthEmailKind;
  recipient: string;
  /** Resume URL for magic-link events. Absent for code / notify events. */
  url?: string;
  /** Numeric OTP for code-bearing events. Absent for magic links / notify. */
  code?: string;
  /** Unix-ms timestamp at which the token / code expires. */
  expiresAt: number;
  /** Recipient's username when known (omitted for invites to new accounts). */
  username?: string;
  /** Free-form payload (e.g. invite-side `roles: string[]`, notify-side `ip`). */
  metadata?: Record<string, unknown>;
}

/**
 * Transport interface implemented by consumers. Aoothjs ships no
 * implementation — wire SendGrid / SES / Twilio / queue here.
 *
 * The workflow `await`s this call, so it should not block on slow downstream
 * transports — push to a queue and return.
 */
export interface EmailSender {
  send(event: AuthEmailEvent): Promise<void>;
}
