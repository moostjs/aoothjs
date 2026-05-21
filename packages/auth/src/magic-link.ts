import { randomBytes } from "node:crypto";

import type { AuthEmailKind } from "./email";

/**
 * Consumer-supplied URL builder. The consumer chooses route, query
 * convention, and base URL — aoothjs does not assume a domain or scheme.
 *
 * Recommended convention: include the token as `?wfs=<token>` so the
 * frontend can mount `<AsWfForm initialToken="...">` to resume the flow.
 *
 * Optional third `ctx` argument lets callers pass a stable per-recipient
 * hint (e.g. `userId`). The invite outlet uses this so the SPA can fall
 * through to a side route for the "already-redeemed" envelope when its
 * second click hits a 410 from the wf state store. Recovery callers
 * ignore the argument.
 */
export type BuildMagicLinkUrl = (
  kind: AuthEmailKind,
  token: string,
  ctx?: { userId?: string },
) => string;

/**
 * 32 bytes of CSPRNG entropy (256 bits) encoded as base64url — 43 chars,
 * URL-safe. Strong enough to survive short TTLs against online guessing.
 */
export function generateMagicLinkToken(): string {
  return randomBytes(32).toString("base64url");
}
