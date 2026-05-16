/**
 * Discriminator for SMS events emitted by the auth workflow stack.
 *
 * Mirrors {@link AuthEmailKind} — kept on a separate union because email and
 * SMS transports do not overlap (email carries `url` for magic links; SMS
 * never does).
 */
export type AuthSmsKind = "login.pincode" | "recovery.pincode" | "invite.pincode";

/**
 * Structured event passed to {@link SmsSender}`.send()` from inside the auth
 * workflows. Flat and serialisable so consumers can route it to any
 * SMS gateway (Twilio, SNS, queue).
 */
export interface AuthSmsEvent {
  kind: AuthSmsKind;
  /** E.164 phone number. */
  recipient: string;
  code: string;
  /** Pincode TTL in ms — convenience for templating "expires in N min". */
  ttlMs: number;
  /** User id when known (omitted for pre-resolved flows). */
  userId?: string;
}

/**
 * Transport interface implemented by consumers. Aoothjs ships no concrete
 * SMS adapter (Twilio / SNS / etc. are consumer-specific) — only this
 * interface. Register via `setProvideRegistry([SmsSender, () => mySender])`.
 *
 * Boot-time invariant: when a workflow's options include SMS as an MFA
 * transport, the workflow constructor throws if no `SmsSender` is
 * registered (fail loud, not at first user attempt).
 */
export interface SmsSender {
  send(event: AuthSmsEvent): Promise<void>;
}
