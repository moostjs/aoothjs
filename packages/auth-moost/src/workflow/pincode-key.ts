import { createHmac } from "node:crypto";
import type { AuthCredential } from "@aooth/auth";
import { key } from "@wooksjs/event-core";

/** Label of the default wf-state secret, `auth.deriveStateKey(WF_STATE_KEY_LABEL)`. */
export const WF_STATE_KEY_LABEL = "wf-state";

/**
 * Internal: the key that seals one-time codes held in workflow state (their
 * keyed digests), published on every trigger request by `WfTriggerProvider`.
 */
export const pincodeKeySlot = key<Buffer>("aooth.pincodeKey");

/**
 * Derive the one-time-code key from a secret — the wf-state secret by default.
 * A separate subkey (HMAC under its own label), never the secret itself, so the
 * code digests and the encapsulated state's AES key never share a key.
 */
export function derivePincodeKey(secret: string | Buffer): Buffer {
  return createHmac("sha256", secret).update("aooth-pincode").digest();
}

/**
 * The one-time-code key of the default wf-state secret — what a default
 * `WfTriggerProvider` publishes, and what `AuthWorkflow.pincodeKey()` uses
 * outside one, so a code minted on either path verifies on the other. Throws
 * `AuthError("INVALID_CONFIG")` when the credential store has no derivable
 * secret (a stateful store): the secret must then be supplied explicitly.
 */
export function defaultPincodeKey(auth: AuthCredential): Buffer {
  return derivePincodeKey(auth.deriveStateKey(WF_STATE_KEY_LABEL));
}
