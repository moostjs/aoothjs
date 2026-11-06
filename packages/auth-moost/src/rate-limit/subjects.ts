import { createHash } from "node:crypto";

import type { EventContext } from "@wooksjs/event-core";
import { current } from "@wooksjs/event-core";
import { useBody } from "@wooksjs/http-body";

/**
 * Internal: a fixed-size, one-way rate-limit subject for a bearer token
 * (`rt:` + 128 bits of its SHA-256) — the raw secret never becomes a counter
 * key in the store.
 */
export function tokenSubject(token: string): string {
  return `rt:${createHash("sha256").update(canonicalToken(token)).digest("base64url").slice(0, 22)}`;
}

/**
 * The base64url-canonical form of a token, segment by segment (`.`-separated,
 * as in a JWT): Node's decoder skips stray characters and reads `+/=`, so
 * `tok=`, `tok `, `tok\n` or a `+/` spelling are one bucket, not several.
 */
function canonicalToken(token: string): string {
  return token
    .split(".")
    .map((segment) => Buffer.from(segment, "base64url").toString("base64url"))
    .join(".");
}

/**
 * Internal: the request body for code that runs before the handler (moost's
 * `@Body()` reuses the parse) — `undefined` when it cannot be parsed.
 */
export async function tryParseBody(ctx: EventContext = current()): Promise<unknown> {
  try {
    return await useBody(ctx).parseBody();
  } catch {
    return undefined;
  }
}

/**
 * Internal key function of the `aooth.token-refresh` policy on
 * `POST /auth/token`: the `refresh_token` of a `grant_type=refresh_token`
 * request, as a {@link tokenSubject}. Any other request skips the policy.
 * Runs before the auth guard (it needs nothing the guard sets); an unparsable
 * body is no token.
 */
export async function oauthRefreshTokenSubject(): Promise<string | null> {
  const body = await tryParseBody();
  const { grant_type: grant, refresh_token: token } =
    (body as { grant_type?: unknown; refresh_token?: unknown } | undefined) ?? {};
  return grant === "refresh_token" && typeof token === "string" && token
    ? tokenSubject(token)
    : null;
}
