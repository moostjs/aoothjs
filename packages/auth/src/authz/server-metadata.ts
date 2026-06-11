/**
 * Strip a trailing slash from an issuer identifier. RFC 8414 mandates EXACT
 * (byte-identical) string comparison of issuer values, so every document that
 * spells the issuer must canonicalize it the same way — same rule as
 * `IdTokenSigner`. Shared by the AS metadata and protected-resource builders.
 */
export function canonicalizeIssuer(issuer: string): string {
  return issuer.replace(/\/$/u, "");
}

/**
 * RFC 8414 Authorization Server Metadata — the discovery document MCP connector
 * clients fetch from `/.well-known/oauth-authorization-server` to locate the
 * authorize / token / registration endpoints. Field names are the wire-format
 * snake_case the RFC mandates; this is the JSON body, serialized as-is.
 */
export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  jwks_uri?: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  code_challenge_methods_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  scopes_supported?: string[];
}

export interface BuildAuthorizationServerMetadataOptions {
  /**
   * The server's issuer identifier. A trailing slash is stripped so the
   * document's `issuer` (and the endpoints derived from it) stay byte-identical
   * to the `iss` a client compares for EXACT string equality (RFC 8414) — same
   * canonicalization rule as `IdTokenSigner`.
   */
  issuer: string;
  /** Override the authorization endpoint. Default: `${issuer}/authorize`. */
  authorizationEndpoint?: string;
  /** Override the token endpoint. Default: `${issuer}/token`. */
  tokenEndpoint?: string;
  /** RFC 7591 dynamic-registration endpoint. Omitted ⇒ field absent. */
  registrationEndpoint?: string;
  /** JWKS document URL (OIDC id_token verification). Omitted ⇒ field absent. */
  jwksUri?: string;
  /** Advertised scopes. Omitted ⇒ field absent (clients may request any). */
  scopesSupported?: string[];
  /**
   * Token-endpoint client-auth methods. Default `["none", "client_secret_post"]`.
   * `"none"` is ALWAYS included even if a custom list omits it — MCP connector
   * clients are public clients (PKCE-bound, no secret) and refuse a server that
   * doesn't advertise it; see {@link buildAuthorizationServerMetadata}.
   */
  tokenEndpointAuthMethodsSupported?: string[];
}

/**
 * Build the RFC 8414 discovery document for this authorization server. Pure —
 * no I/O, no framework: mount the result on any HTTP stack (including the
 * RFC 8414 path-insertion form rooted at the HTTP origin,
 * `/.well-known/oauth-authorization-server/<issuer-path>`).
 *
 * Capability fields are fixed to what the server actually implements:
 * `response_types_supported` `["code"]`, `grant_types_supported`
 * `["authorization_code"]`, `code_challenge_methods_supported` `["S256"]`
 * (PKCE is mandatory — it is the binding for public clients). Optional fields
 * are omitted entirely (no `undefined` keys) so the serialized JSON carries
 * only what was configured.
 */
export function buildAuthorizationServerMetadata(
  opts: BuildAuthorizationServerMetadataOptions,
): AuthorizationServerMetadata {
  // Canonicalize once — issuer + derived endpoints must be byte-identical
  // across config spellings (RFC 8414 exactness rule).
  const issuer = canonicalizeIssuer(opts.issuer);
  const authMethods = opts.tokenEndpointAuthMethodsSupported ?? ["none", "client_secret_post"];
  return {
    issuer,
    authorization_endpoint: opts.authorizationEndpoint ?? `${issuer}/authorize`,
    token_endpoint: opts.tokenEndpoint ?? `${issuer}/token`,
    ...(opts.registrationEndpoint !== undefined && {
      registration_endpoint: opts.registrationEndpoint,
    }),
    ...(opts.jwksUri !== undefined && { jwks_uri: opts.jwksUri }),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    // Public clients require "none" — prepend it rather than trust the caller.
    token_endpoint_auth_methods_supported: authMethods.includes("none")
      ? authMethods
      : ["none", ...authMethods],
    ...(opts.scopesSupported !== undefined && { scopes_supported: opts.scopesSupported }),
  };
}
