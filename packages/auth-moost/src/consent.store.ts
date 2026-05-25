import { Injectable } from "moost";

import type { ConsentEvent } from "./workflows/auth-workflow.base";

/**
 * Descriptor for a single consent prompt. Customers' ConsentStore.getPendingConsents
 * returns an array of these — the workflow transports them via `@wf.context.pass`
 * to the SPA carrier form, which renders one row per descriptor through the
 * `AsConsentArray` component (`@atscript/vue-aooth`). The user-submitted
 * `consents: string[]` field on the carrier form posts back the SUBSET of
 * `id`s the user accepted; the server-side `processInlineConsent` helper
 * silently drops any ids that don't match a current descriptor (audit-grade
 * "what user saw is what server records" invariant — preventing an attacker
 * from forging audit rows for consents the user was never shown).
 */
export interface ConsentDescriptor {
  /** Stable identifier — committed to the user-submitted `consents: string[]`
   *  array and stamped on the persisted `ConsentEvent` (customer-defined:
   *  `'terms'`, `'marketing'`, `'jurisdiction-gdpr'`, …). */
  id: string;
  /** User-facing label / disclosure text. Markdown links are allowed; the
   *  SPA component will sanitize-render. */
  text: string;
  /**
   * When present and non-empty, the consent is MANDATORY and this string IS
   * the per-row error message surfaced by `AsConsentArray` (and the
   * server-side `processInlineConsent` form-level error) when the user
   * submits without ticking it. Absent or empty string ⇒ optional consent —
   * a `ConsentEvent` with `accepted: false` is still persisted so the audit
   * record proves the user was asked.
   */
  required?: string;
  /** Stamped onto persisted ConsentEvent for versioned policies (terms, ...). */
  version?: string;
}

/**
 * Injectable DI seam for consent persistence + the customer-defined consent
 * universe. SINGLETON-scoped (one instance per app lifetime). All methods are
 * no-op defaults — customers extend this class and replace via
 * `createReplaceRegistry([ConsentStore, MyConsentStore])`.
 */
@Injectable() // SINGLETON
export class ConsentStore {
  /**
   * Returns descriptors for consents this user still needs to accept on the
   * next prompt boundary. Empty array → no consent step renders. The workflow
   * passes its identity + (optionally) the channel it's about to use so the
   * customer's impl can prompt different consent sets per workflow/channel.
   */
  async getPendingConsents(
    _username: string | undefined,
    _ctx: { workflow: string; channel?: "email" | "sms" },
  ): Promise<ConsentDescriptor[]> {
    return [];
  }

  /**
   * Persist a batch of captured consent events. Default: no-op. Override to
   * write to your audit table / event store / whatever your legal team
   * requires.
   */
  async save(_username: string, _events: ConsentEvent[]): Promise<void> {
    // no-op default
  }

  /**
   * Read consent history for a user, optionally filtered by event id.
   * Used by getPendingConsents impls that want to compute "has the user
   * already accepted version vN" without maintaining a separate index.
   */
  async read(_username: string, _filter?: { id?: string }): Promise<ConsentEvent[]> {
    return [];
  }

  /**
   * Fired by LoginWorkflow's verify/:channel step AFTER pincode validates,
   * i.e., AFTER channel ownership is confirmed. The disclosure text is the
   * literal copy the user saw beneath the input field at ask/:channel time
   * (resolveOtpDisclosure result) — passed through so the customer's record
   * pins exactly what was shown to the user.
   *
   * Default: no-op. Disclosure-only is sufficient for transactional OTPs
   * under TCPA/PECR/CASL/GDPR. Override if your jurisdiction or legal team
   * requires affirmative consent capture for OTP channels.
   */
  async recordOtpChannelConsent(
    _username: string,
    _channel: "email" | "sms",
    _target: string,
    _disclosure: string,
  ): Promise<void> {
    // no-op default
  }
}
