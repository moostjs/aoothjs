import type { CredentialState } from "./types";

/**
 * The reserved {@link CredentialState} envelope keys (plus `token`, attached by
 * `listForUser`/atscript-db rows). A consumer's typed payload fields are
 * everything on a `CredentialState & TPayload` object that is NOT one of these.
 *
 * KEEP IN SYNC with {@link CredentialState}: adding an envelope field without
 * adding it here would leak that field into the extracted payload (and onto
 * {@link import("./types").AuthContext}). A payload field must never reuse one
 * of these names.
 */
const ENVELOPE_KEYS: ReadonlySet<string> = new Set<keyof CredentialState | "token">([
  "userId",
  "issuedAt",
  "expiresAt",
  "metadata",
  "kind",
  "parentCredentialId",
  "rotatedAt",
  "sessionId",
  "lastSeenAt",
  "token",
]);

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
