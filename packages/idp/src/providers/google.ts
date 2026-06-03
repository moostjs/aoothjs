import { OidcProvider, type OidcProviderOptions } from "./oidc";

/** Google's stable OIDC issuer — endpoints + JWKS are discovered from it. */
const GOOGLE_ISSUER = "https://accounts.google.com";

/** Google options = OIDC options minus the pinned `id`/`issuer`. */
export type GoogleProviderOptions = Omit<OidcProviderOptions, "id" | "issuer">;

/**
 * Google Sign-In (OIDC). Pins `id: 'google'`, the Google issuer, and `RS256`
 * (Google's only ID-token alg). Everything else — discovery, JWKS rotation,
 * the full §7 validation — is inherited from {@link OidcProvider}.
 */
export class GoogleProvider extends OidcProvider {
  constructor(opts: GoogleProviderOptions) {
    super({
      ...opts,
      id: "google",
      issuer: GOOGLE_ISSUER,
      idTokenSigningAlgs: opts.idTokenSigningAlgs ?? ["RS256"],
    });
  }
}
