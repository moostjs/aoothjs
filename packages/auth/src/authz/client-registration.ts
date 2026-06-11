import { type Clock, defaultClock } from "../utils/clock";
import { isLoopbackRedirectUri } from "./client-policy";
import {
  type DynamicClient,
  type DynamicClientStore,
  type NewDynamicClient,
} from "./dynamic-client-store";

/**
 * RFC 7591 §3.2.2 error vocabulary — deliberately separate from
 * `AuthorizeErrorCode`: registration errors are a different wire contract
 * (`400 { error, error_description }`) than the authorize/token taxonomy.
 */
export type ClientRegistrationErrorCode = "invalid_redirect_uri" | "invalid_client_metadata";

/** A typed RFC 7591 registration failure; `message` becomes `error_description`. */
export class ClientRegistrationError extends Error {
  readonly code: ClientRegistrationErrorCode;
  constructor(code: ClientRegistrationErrorCode, message: string) {
    super(message);
    this.name = "ClientRegistrationError";
    this.code = code;
  }
}

/** Grant/response types the v1 authorization server supports (auth-code + PKCE only). */
const SUPPORTED_GRANT_TYPES = ["authorization_code"];
const SUPPORTED_RESPONSE_TYPES = ["code"];

/** RFC 6749 §3.3 scope-token charset: printable ASCII minus space, `"` and `\`. */
const SCOPE_TOKEN_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/u;

export interface ClientRegistrationValidationOptions {
  /** Max `redirect_uris` entries (anonymous endpoint — rows must stay small). Default 5. */
  maxRedirectUris?: number;
  /** Max length of a single redirect URI. Default 512. */
  maxRedirectUriLength?: number;
  /** Max `client_name` length (after sanitization). Default 128. */
  maxClientNameLength?: number;
  /** Max `scope` string length. Default 256. */
  maxScopeLength?: number;
  /**
   * Registration-time scope filter: the stored `scope` is the intersection of
   * the requested tokens with this list. Omit to record the requested scope
   * as-is. NOTE this is an upper bound on what the client may LATER request —
   * the authorize-time grant is additionally bounded by
   * `DynamicClientPolicyOptions.allowedScopes` (the server allow-list).
   */
  allowedScopes?: string[];
}

const DEFAULT_MAX_REDIRECT_URIS = 5;
const DEFAULT_MAX_REDIRECT_URI_LENGTH = 512;
const DEFAULT_MAX_CLIENT_NAME_LENGTH = 128;
const DEFAULT_MAX_SCOPE_LENGTH = 256;

/**
 * `client_name` is attacker-supplied text that ends up on the consent prompt.
 * Strip every control (Cc) and format (Cf) character — that kills CR/LF, the
 * Unicode bidi overrides (U+202A–202E, U+2066–2069) used to visually reverse
 * a name, and zero-width characters used to forge lookalikes — then trim and
 * cap. Rendering it as a TEXT node (never markup) is the consent form's job;
 * this is defense in depth, not the whole defense.
 */
function sanitizeClientName(name: string, maxLength: number): string | undefined {
  // oxlint-disable-next-line no-control-regex -- stripping control chars is the point
  const cleaned = name.replace(/[\p{Cc}\p{Cf}]/gu, "").trim();
  if (cleaned.length === 0) return undefined;
  return cleaned.slice(0, maxLength);
}

function asStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new ClientRegistrationError(
      "invalid_client_metadata",
      `${field} must be an array of strings`,
    );
  }
  return value as string[];
}

/**
 * `true` when `uri` is an acceptable dynamic-client redirect target (OAUTH.md
 * R2): an `https://` URL with an explicit host (stored for EXACT matching — no
 * wildcards, no prefixes) or a loopback literal per the Tier-1 RFC 8252 rules.
 * Custom schemes are rejected in v1. A fragment is rejected outright (RFC 6749
 * §3.1.2: the redirection endpoint URI MUST NOT include a fragment component).
 */
function isAcceptableRedirectUri(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.hash !== "") return false;
  if (isLoopbackRedirectUri(uri)) return true;
  return (
    url.protocol === "https:" && url.hostname !== "" && url.username === "" && url.password === ""
  );
}

/**
 * Validate + normalize an RFC 7591 registration request body into a
 * {@link NewDynamicClient}, or THROW a {@link ClientRegistrationError}.
 *
 * Normalization is allowed by RFC 7591 §2 (the server MAY replace requested
 * metadata with its own values) and is load-bearing for real connectors:
 * `grant_types` / `response_types` are INTERSECTED with what the server
 * supports (a connector requesting `["authorization_code", "refresh_token"]`
 * registers with `["authorization_code"]` — the 201 echo of the narrowed set
 * is the contract) rather than rejected. `token_endpoint_auth_method` defaults
 * to `"none"` when absent (v1 is public-clients-only, so the RFC's
 * `client_secret_basic` default is unsupported), but an EXPLICIT non-`"none"`
 * ask is rejected — never silently downgrade a client that asked for a secret.
 * Unknown fields are ignored and never echoed.
 */
export function validateClientRegistration(
  body: unknown,
  opts?: ClientRegistrationValidationOptions,
): NewDynamicClient {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new ClientRegistrationError(
      "invalid_client_metadata",
      "registration request must be a JSON object",
    );
  }
  const req = body as Record<string, unknown>;
  const maxUris = opts?.maxRedirectUris ?? DEFAULT_MAX_REDIRECT_URIS;
  const maxUriLength = opts?.maxRedirectUriLength ?? DEFAULT_MAX_REDIRECT_URI_LENGTH;

  // redirect_uris — required, non-empty, every entry validated (THE open-redirect gate).
  if (req.redirect_uris === undefined) {
    throw new ClientRegistrationError("invalid_redirect_uri", "redirect_uris is required");
  }
  const redirectUris = [...new Set(asStringArray(req.redirect_uris, "redirect_uris"))];
  if (redirectUris.length === 0) {
    throw new ClientRegistrationError("invalid_redirect_uri", "redirect_uris must be non-empty");
  }
  if (redirectUris.length > maxUris) {
    throw new ClientRegistrationError(
      "invalid_redirect_uri",
      `redirect_uris accepts at most ${maxUris} entries`,
    );
  }
  for (const uri of redirectUris) {
    if (uri.length > maxUriLength || !isAcceptableRedirectUri(uri)) {
      throw new ClientRegistrationError(
        "invalid_redirect_uri",
        "each redirect_uri must be an https URL with an explicit host or a loopback literal, without a fragment",
      );
    }
  }

  // token_endpoint_auth_method — "none" only in v1 (public clients; PKCE is the binding).
  const authMethod = req.token_endpoint_auth_method ?? "none";
  if (authMethod !== "none") {
    throw new ClientRegistrationError(
      "invalid_client_metadata",
      'only token_endpoint_auth_method "none" is supported',
    );
  }

  // grant_types / response_types — intersect with supported, require a usable result.
  const grantTypes =
    req.grant_types === undefined
      ? [...SUPPORTED_GRANT_TYPES]
      : asStringArray(req.grant_types, "grant_types").filter((g) =>
          SUPPORTED_GRANT_TYPES.includes(g),
        );
  if (grantTypes.length === 0) {
    throw new ClientRegistrationError(
      "invalid_client_metadata",
      "grant_types must include authorization_code",
    );
  }
  const responseTypes =
    req.response_types === undefined
      ? [...SUPPORTED_RESPONSE_TYPES]
      : asStringArray(req.response_types, "response_types").filter((r) =>
          SUPPORTED_RESPONSE_TYPES.includes(r),
        );
  if (responseTypes.length === 0) {
    throw new ClientRegistrationError(
      "invalid_client_metadata",
      "response_types must include code",
    );
  }

  // client_name — optional untrusted display text; sanitized, never markup.
  let clientName: string | undefined;
  if (req.client_name !== undefined) {
    if (typeof req.client_name !== "string") {
      throw new ClientRegistrationError("invalid_client_metadata", "client_name must be a string");
    }
    clientName = sanitizeClientName(
      req.client_name,
      opts?.maxClientNameLength ?? DEFAULT_MAX_CLIENT_NAME_LENGTH,
    );
  }

  // scope — optional; RFC 6749 token charset, length-capped, optionally filtered.
  let scope: string | undefined;
  if (req.scope !== undefined) {
    if (typeof req.scope !== "string") {
      throw new ClientRegistrationError("invalid_client_metadata", "scope must be a string");
    }
    if (req.scope.length > (opts?.maxScopeLength ?? DEFAULT_MAX_SCOPE_LENGTH)) {
      throw new ClientRegistrationError("invalid_client_metadata", "scope is too long");
    }
    const tokens = req.scope.split(/\s+/u).filter(Boolean);
    if (tokens.some((t) => !SCOPE_TOKEN_RE.test(t))) {
      throw new ClientRegistrationError(
        "invalid_client_metadata",
        "scope contains invalid characters",
      );
    }
    const kept = opts?.allowedScopes
      ? tokens.filter((t) => opts.allowedScopes!.includes(t))
      : tokens;
    if (kept.length > 0) scope = kept.join(" ");
  }

  return {
    redirectUris,
    tokenEndpointAuthMethod: "none",
    grantTypes,
    responseTypes,
    ...(clientName !== undefined && { clientName }),
    ...(scope !== undefined && { scope }),
  };
}

export interface DynamicClientRegistrationOptions {
  store: DynamicClientStore;
  /**
   * Hard cap on stored registrations — `/register` is anonymous, so this
   * bounds storage. REJECT-when-full (never evict): evicting a used row
   * strands a connector that cached its `client_id`. Default 1000.
   */
  maxClients?: number;
  /**
   * Age after which a NEVER-USED registration (no `lastUsedAt`) is
   * garbage-collected — lazily, on the next `register()` call, before the cap
   * check. Omit to disable GC.
   */
  unusedClientTtlMs?: number;
  /**
   * Pluggable abuse guard, called with the validated metadata BEFORE anything
   * is stored. Throw a {@link ClientRegistrationError} to reject with a 7591
   * error; any other throw is a server fault (the endpoint answers 500).
   * Rate limiting belongs at the consumer's ingress, not here.
   */
  guard?: (args: { metadata: NewDynamicClient }) => void | Promise<void>;
  validation?: ClientRegistrationValidationOptions;
  /** Injectable clock for deterministic GC tests. Defaults to {@link defaultClock}. */
  clock?: Clock;
}

const DEFAULT_MAX_CLIENTS = 1000;

/**
 * The RFC 7591 registration operation behind `POST {issuer}/register`
 * (OAUTH.md R2): validate → guard → lazy GC of never-used rows → hard cap →
 * persist. Framework-free — `@aooth/auth-moost`'s controller endpoint is a
 * thin HTTP adapter over `register()`, and non-moost servers can call it
 * directly.
 */
export class DynamicClientRegistration {
  private readonly store: DynamicClientStore;
  private readonly maxClients: number;
  private readonly unusedClientTtlMs?: number;
  private readonly guard?: DynamicClientRegistrationOptions["guard"];
  private readonly validation?: ClientRegistrationValidationOptions;
  private readonly clock: Clock;

  constructor(opts: DynamicClientRegistrationOptions) {
    this.store = opts.store;
    this.maxClients = opts.maxClients ?? DEFAULT_MAX_CLIENTS;
    this.unusedClientTtlMs = opts.unusedClientTtlMs;
    this.guard = opts.guard;
    this.validation = opts.validation;
    this.clock = opts.clock ?? defaultClock;
  }

  /** Validate and persist a registration request body; returns the minted client. */
  async register(body: unknown): Promise<DynamicClient> {
    const metadata = validateClientRegistration(body, this.validation);
    await this.guard?.({ metadata });
    if (this.unusedClientTtlMs !== undefined) {
      await this.store.deleteUnusedBefore(this.clock.now() - this.unusedClientTtlMs);
    }
    if ((await this.store.count()) >= this.maxClients) {
      throw new ClientRegistrationError("invalid_client_metadata", "registration limit reached");
    }
    return this.store.create(metadata);
  }
}
