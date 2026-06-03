import { timingSafeEqual } from "node:crypto";
import type { TCookieAttributesInput } from "@wooksjs/event-http";

/**
 * Name of the double-submit anti-CSRF cookie set at `/:provider/start` and
 * verified in `oauth-exchange`. Holds the signed-state `random`; the callback
 * proves it speaks for the same browser that started the flow by matching the
 * cookie value against the verified `state.random` (RFC IDP.md §7).
 */
export const OAUTH_CSRF_COOKIE = "aooth_oauth";

/**
 * Cookie attributes for the CSRF cookie. `SameSite=Lax` (NOT `Strict`) so the
 * top-level GET navigation BACK from the provider still carries it; `httpOnly`
 * so script can't read it; short `maxAge` matched to the state TTL. `secure` is
 * caller-controlled (off for the http test harness, on in production).
 */
export function oauthCsrfCookieAttrs(opts: {
  secure: boolean;
  /** Cookie lifetime in seconds — match the signed-state TTL (default 600). */
  maxAgeSec?: number;
  path?: string;
}): TCookieAttributesInput {
  return {
    httpOnly: true,
    secure: opts.secure,
    sameSite: "Lax",
    path: opts.path ?? "/",
    // wooks' `maxAge` is MILLISECONDS (it renders `Max-Age` in seconds by
    // dividing by 1000), so convert from the seconds-based knob.
    maxAge: (opts.maxAgeSec ?? 600) * 1000,
  };
}

/**
 * Constant-time string equality — used for the CSRF cookie ↔ state.random
 * match so a mismatch can't be probed by timing. Returns `false` (never throws)
 * for non-strings or length mismatch.
 *
 * Package-internal: `export`ed for the intra-package `oauth-exchange` import, but
 * intentionally NOT re-exported from the package index — it mirrors the private
 * constant-time compares elsewhere in the stack (e.g. `deviceTrustSafeEqual` in
 * `@aooth/user`) rather than being a public API contract. If these ever warrant a
 * single audited primitive, the right home is a `safeStringEqual` export from
 * `@aooth/user` (the lowest shared layer), consumed by both — not a public symbol here.
 */
export function safeEqual(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
