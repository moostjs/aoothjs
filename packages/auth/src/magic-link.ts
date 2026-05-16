import { randomBytes } from "node:crypto";

import type { AuthEmailKind } from "./email";

/**
 * Consumer-supplied URL builder. The consumer chooses route, query
 * convention, and base URL — aoothjs does not assume a domain or scheme.
 *
 * Recommended convention: include the token as `?wfs=<token>` so the
 * frontend can mount `<AsWfForm initialToken="...">` to resume the flow.
 */
export type BuildMagicLinkUrl = (kind: AuthEmailKind, token: string) => string;

/**
 * 32 bytes of CSPRNG entropy (256 bits) encoded as base64url — 43 chars,
 * URL-safe. Strong enough to survive short TTLs against online guessing.
 */
export function generateMagicLinkToken(): string {
  return randomBytes(32).toString("base64url");
}
