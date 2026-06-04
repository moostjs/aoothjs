import type { CredentialState } from "./types";

/**
 * The reserved {@link CredentialState} envelope keys (plus `token`, attached by
 * `listForUser`/atscript-db rows). A consumer's typed payload fields are
 * everything on a `CredentialState & TPayload` object that is NOT one of these.
 *
 * The `Record<…, true>` shape makes this self-syncing with {@link CredentialState}:
 * adding an envelope field without listing it here is a COMPILE error (the
 * record would be missing a required key), so a new field can never silently
 * leak into the extracted payload (and onto {@link import("./types").AuthContext}).
 * A payload field must never reuse one of these names.
 */
const ENVELOPE_KEY_FLAGS: Record<keyof CredentialState | "token", true> = {
  userId: true,
  issuedAt: true,
  expiresAt: true,
  metadata: true,
  kind: true,
  parentCredentialId: true,
  rotatedAt: true,
  sessionId: true,
  lastSeenAt: true,
  token: true,
};
const ENVELOPE_KEYS: ReadonlySet<string> = new Set(Object.keys(ENVELOPE_KEY_FLAGS));

/**
 * Extract a credential's typed payload — every own enumerable key that is not a
 * reserved {@link CredentialState} envelope key. Used by the field-mapping
 * stores (JWT codec, atscript-db row adapter) to round-trip customer root
 * fields, and by the orchestrator to surface them on `AuthContext` without
 * leaking envelope internals (e.g. `parentCredentialId`).
 */
export function credentialPayloadOf<TPayload extends object = object>(state: object): TPayload {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(state)) {
    if (!ENVELOPE_KEYS.has(key)) out[key] = value;
  }
  return out as TPayload;
}
