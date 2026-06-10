/**
 * Build the client redirect URL for an authorization-server result (RFC 6749
 * §4.1.2 / §4.1.2.1): append the result params (`code` on success, `error` on
 * failure) and echo the client's `state` when it sent one. The single home for
 * this URL contract — the controller's fail-soft redirect and the workflow's
 * deny / code-mint terminals all build the same shape, only the transport
 * (controller response vs `finishWf` envelope) differs.
 */
export function authzRedirectUrl(
  redirectUri: string,
  params: { code?: string; error?: string; state?: string },
): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url.toString();
}
