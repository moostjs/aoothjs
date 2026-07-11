import type { AuthEmailKind } from "./email";
import { generateOpaqueToken } from "./utils/opaque-token";

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

/** A magic-link token is a plain {@link generateOpaqueToken} mint. */
export function generateMagicLinkToken(): string {
  return generateOpaqueToken();
}
