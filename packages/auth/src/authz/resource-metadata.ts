import { canonicalizeIssuer } from "./server-metadata";

/**
 * RFC 9728 Protected Resource Metadata — the document a resource server (an
 * MCP server, an API) publishes at `/.well-known/oauth-protected-resource` so
 * clients can discover WHICH authorization server(s) guard it. Field names are
 * the wire-format snake_case; this is the JSON body, serialized as-is.
 */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
  scopes_supported?: string[];
  resource_name?: string;
}

export interface BuildProtectedResourceMetadataOptions {
  /** The resource identifier — the canonical URL of the protected resource. */
  resource: string;
  /**
   * Issuer identifiers of the authorization server(s). Trailing slashes are
   * stripped: clients match these against the AS metadata `issuer` for EXACT
   * string equality (RFC 8414), so both documents must spell it byte-identically.
   */
  authorizationServers: string[];
  /** Scopes the resource understands. Omitted ⇒ field absent. */
  scopesSupported?: string[];
  /** How the bearer token may be presented. Default `["header"]` (RFC 6750 §2.1). */
  bearerMethodsSupported?: string[];
  /** Human-readable display name. Omitted ⇒ field absent. */
  resourceName?: string;
}

/**
 * Build the RFC 9728 protected-resource document. Pure — no I/O, no framework;
 * mount it on any HTTP stack. Optional fields are omitted entirely (no
 * `undefined` keys) so the serialized JSON carries only what was configured.
 */
export function buildProtectedResourceMetadata(
  opts: BuildProtectedResourceMetadataOptions,
): ProtectedResourceMetadata {
  return {
    resource: opts.resource,
    authorization_servers: opts.authorizationServers.map((iss) => canonicalizeIssuer(iss)),
    bearer_methods_supported: opts.bearerMethodsSupported ?? ["header"],
    ...(opts.scopesSupported !== undefined && { scopes_supported: opts.scopesSupported }),
    ...(opts.resourceName !== undefined && { resource_name: opts.resourceName }),
  };
}

export interface WwwAuthenticateBearerChallengeOptions {
  /**
   * URL of the protected-resource document (RFC 9728 §5.1) — emitted as
   * `resource_metadata="..."` so a client receiving a 401 can discover the
   * authorization server without out-of-band configuration.
   */
  resourceMetadataUrl?: string;
  /** RFC 6750 §3.1 error code (`invalid_token`, `insufficient_scope`, ...). */
  error?: string;
  /** Human-readable detail — emitted as `error_description="..."`. */
  errorDescription?: string;
  /** Scope(s) required to access the resource (space-separated). */
  scope?: string;
  /** Protection-space identifier (RFC 7235). */
  realm?: string;
}

/**
 * Header-injection defense: challenge parameter values can carry
 * attacker-influenced input (an `error_description` echoing request data, a
 * scope from a token). A raw CR/LF would terminate the header and let that
 * input inject arbitrary response headers (response splitting), so CR/LF — and
 * every other C0 control char plus DEL — are STRIPPED outright. `\` and `"`
 * are then backslash-escaped per the RFC 7235 quoted-string grammar so a value
 * cannot close its quote and smuggle extra challenge params.
 */
function sanitizeQuotedStringValue(value: string): string {
  // oxlint-disable-next-line no-control-regex -- stripping control chars is the point
  return value.replace(/[\u0000-\u001F\u007F]/gu, "").replace(/(["\\])/gu, "\\$1");
}

/**
 * Build the VALUE of an RFC 6750 `WWW-Authenticate` Bearer challenge, e.g.
 * `Bearer resource_metadata="https://...", error="invalid_token"`. With no
 * options (or all absent) it degrades to the bare scheme `Bearer`. Every
 * parameter is emitted as a quoted-string (RFC 6750 style) in a fixed order:
 * `realm`, `error`, `error_description`, `resource_metadata`, `scope`. All
 * values pass through {@link sanitizeQuotedStringValue} — see its security note.
 */
export function buildWwwAuthenticateBearerChallenge(
  opts?: WwwAuthenticateBearerChallengeOptions,
): string {
  const params: string[] = [];
  const push = (name: string, value: string | undefined): void => {
    if (value !== undefined) params.push(`${name}="${sanitizeQuotedStringValue(value)}"`);
  };
  push("realm", opts?.realm);
  push("error", opts?.error);
  push("error_description", opts?.errorDescription);
  push("resource_metadata", opts?.resourceMetadataUrl);
  push("scope", opts?.scope);
  return params.length === 0 ? "Bearer" : `Bearer ${params.join(", ")}`;
}
