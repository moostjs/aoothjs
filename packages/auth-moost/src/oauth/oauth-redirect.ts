/**
 * Open-redirect defense for the post-login `redirect` carried across the OAuth
 * bounce (RFC IDP.md §7). The provider round-trips whatever target the SPA
 * asked for, so it MUST be validated before it is signed into `state` AND again
 * before it is honored — an attacker who can seed the `redirect` could
 * otherwise turn a trusted callback into an open redirector (phishing /
 * token-leak via `//evil.test`, `/\evil.test`, `https://evil.test`,
 * `javascript:…`).
 *
 * Policy: accept ONLY a same-origin, absolute-path relative URL — it must start
 * with a single `/`, contain no backslashes (some browsers fold `\` → `/`), and
 * carry no control/whitespace characters (which browsers may strip, changing
 * the parsed target). Everything else falls back to the caller's default.
 */
export function isSafeRelativeRedirect(target: string | undefined): target is string {
  if (typeof target !== "string" || target.length === 0) return false;
  // Must be an absolute path on this origin.
  if (target[0] !== "/") return false;
  // Reject protocol-relative (`//host`, `/\host`) — both navigate cross-origin.
  if (target[1] === "/" || target[1] === "\\") return false;
  // Reject backslashes anywhere — browsers may normalize `\` to `/`.
  if (target.includes("\\")) return false;
  // Reject control chars / whitespace (NUL..space, DEL) that can be stripped
  // client-side to smuggle a different target past this check.
  for (let i = 0; i < target.length; i++) {
    const code = target.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) return false;
  }
  return true;
}

/**
 * Return `requested` when it is a safe same-origin relative redirect, else
 * `fallback`. Used at `/start` (before signing) and re-checked in
 * `oauth-exchange` (before honoring) — defense in depth around the signed
 * round-trip.
 */
export function resolveOAuthRedirect(requested: string | undefined, fallback: string): string {
  return isSafeRelativeRedirect(requested) ? requested : fallback;
}
