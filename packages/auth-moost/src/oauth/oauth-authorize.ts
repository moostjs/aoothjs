import { generateRandomState, type OAuthProviderRegistry } from "@aooth/idp";

/** Signed-state + CSRF-cookie + authorize-request TTL (seconds). Matches `signState`'s default. */
export const OAUTH_TTL_SEC = 600;

export interface OAuthAuthorizeInput {
  /** Already-resolved (open-redirect-screened) post-login app redirect. */
  redirect: string;
  /**
   * Initiating authenticated user id — set ONLY for account-LINK (`/:provider/
   * link`). Bound into the HS256-signed `state` (tamper-proof, server-minted) so
   * `sso-callback` links the verified identity to THIS user. Absent for login.
   */
  userId?: string;
}

/**
 * Build the leg-1 federated-login authorization request — STATELESS, no flow
 * store. Mints a fresh non-secret `seed`, DERIVES the PKCE verifier + OIDC nonce
 * from it (`registry.deriveSeededPkce`), signs `{ random: seed, provider,
 * redirect, [userId] }` into `state`, and returns the provider authorize URL +
 * the `seed`. The caller drops the `seed` into the Lax double-submit CSRF cookie
 * via its OWN sink (`useResponse().setCookie` for a REST 302, the `WfFinished`
 * envelope `cookies` map for a wf-outlet redirect) and uses
 * {@link OAUTH_TTL_SEC} for the cookie's `maxAge`. `sso-callback` re-derives the
 * identical verifier from `state.random`, so nothing secret ever rides in the URL.
 *
 * Single home for the seed → PKCE → state → authorize-URL derivation, shared by
 * `OAuthController.begin` (REST `/:provider/link`) and `AuthWorkflow.beginSso`
 * (login-wf SSO leg) so the two security-critical legs cannot drift apart. The
 * caller resolves + validates the provider first (preserving its own
 * unknown-provider error semantics) and passes the resolved instance in.
 */
export async function buildOAuthAuthorizeRequest(
  registry: OAuthProviderRegistry,
  provider: ReturnType<OAuthProviderRegistry["require"]>,
  input: OAuthAuthorizeInput,
): Promise<{ seed: string; authUrl: string }> {
  const seed = generateRandomState();
  const { nonce, challenge } = registry.deriveSeededPkce(seed);
  const state = await registry.signState(
    {
      random: seed,
      provider: provider.id,
      redirect: input.redirect,
      ...(input.userId !== undefined && { userId: input.userId }),
    },
    { ttlSec: OAUTH_TTL_SEC },
  );
  const authUrl = await provider.authorizationUrl({
    redirectUri: registry.redirectUri(provider.id),
    state,
    codeChallenge: challenge,
    nonce,
  });
  return { seed, authUrl };
}
