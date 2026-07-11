// Dye-token shim — see controller-utils.ts for why.
const g = globalThis as Record<string, unknown>;
for (const key of [
  "__DYE_YELLOW__",
  "__DYE_RED_BRIGHT__",
  "__DYE_GREEN__",
  "__DYE_DIM__",
  "__DYE_DIM_OFF__",
  "__DYE_COLOR_OFF__",
]) {
  if (!(key in g)) g[key] = "";
}

import { createHash, generateKeyPairSync } from "node:crypto";

import { AuthCredential, CredentialStoreMemory, type SessionInfo } from "@aooth/auth";
import {
  type AuthCodeStore,
  AuthCodeStoreMemory,
  type ClientRedirectPolicy,
  ClientRegistrationError,
  CompositeClientPolicy,
  type DynamicClient,
  DynamicClientPolicy,
  DynamicClientRegistration,
  DynamicClientStoreMemory,
  hashClientSecret,
  IdTokenSigner,
  LoopbackClientPolicy,
  OidcClaimsResolver,
  type PendingAuthorizationStore,
  PendingAuthorizationStoreMemory,
  RegisteredClientPolicy,
} from "@aooth/auth/authz";
import { MoostHttp } from "@moostjs/event-http";
import { createHttpApp } from "@wooksjs/event-http";
import { Controller, createProvideRegistry, getMoostInfact, Inherit, Inject, Moost } from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import { Wooks } from "wooks";

import { authGuardInterceptor } from "../auth.guard";
import { AuthorizeController } from "../authz/authorize.controller";
import { AUTHZ_BINDING_COOKIE } from "../authz/authz-binding";
import {
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "../authz/authz-tokens";
import { parseCookieValue } from "./controller-utils";

const LOOPBACK = "http://127.0.0.1:5000/callback";
const pkce = (verifier: string): string =>
  createHash("sha256").update(verifier).digest("base64url");

interface Harness {
  request: (
    input: string,
    init?: RequestInit,
  ) => Promise<{
    status: number;
    body: unknown;
    location: string | null;
    setCookies: string[];
  }>;
  auth: AuthCredential;
  pending: PendingAuthorizationStoreMemory;
  codes: AuthCodeStoreMemory;
}

/** Wrap `http.request`: JSON-parse the body when possible, collect Location + Set-Cookie. */
function makeRequester(http: MoostHttp): Harness["request"] {
  return async (input, init = {}) => {
    const response = await http.request(input, init);
    if (!response) return { status: 0, body: null, location: null, setCookies: [] };
    const text = await response.text();
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      /* leave as text */
    }
    return {
      status: response.status,
      body,
      location: response.headers.get("location"),
      setCookies: response.headers.getSetCookie(),
    };
  };
}

async function buildApp(): Promise<Harness> {
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const http = moost.adapter(new MoostHttp(createHttpApp(undefined, new Wooks())));

  const auth = new AuthCredential({
    store: new CredentialStoreMemory(),
    method: "token",
    accessTtl: 60_000,
  });
  const pending = new PendingAuthorizationStoreMemory();
  const codes = new AuthCodeStoreMemory();
  const policy = new LoopbackClientPolicy();

  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => auth],
      [CLIENT_REDIRECT_POLICY_TOKEN, () => policy],
      [PENDING_AUTHORIZATION_STORE_TOKEN, () => pending],
      [AUTH_CODE_STORE_TOKEN, () => codes],
    ),
  );
  moost.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
  // biome-ignore lint/suspicious/noExplicitAny: registerControllers' prefixed-tuple shape.
  moost.registerControllers(AuthorizeController as any);
  await moost.init();

  return { request: makeRequester(http), auth, pending, codes };
}

const form = (fields: Record<string, string>): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(fields).toString(),
});

describe("AuthorizeController GET /auth/authorize", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await buildApp();
  });

  it("302s a valid loopback request to the login page with the pending handle", async () => {
    const res = await h.request(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
        `&state=cs&code_challenge=chal&code_challenge_method=S256&scope=api`,
    );
    expect(res.status).toBe(302);
    expect(res.location).toMatch(/^\/login\?authz=/);

    const handle = new URLSearchParams(res.location!.split("?")[1]).get("authz")!;
    const row = await h.pending.get(handle);
    expect(row?.redirectUri).toBe(LOOPBACK);
    expect(row?.clientState).toBe("cs");
    expect(row?.codeChallenge).toBe("chal");
    expect(row?.scope).toBe("api");
    expect(row?.tokenPolicy.kind).toBe("cli-session");

    // Browser binding (AUTH-SERVER.md §6): a high-entropy `binding` is recorded
    // on the pending row AND dropped as the httpOnly `aooth_authz` cookie, so a
    // phished handle is inert in any other browser. The two must match exactly.
    expect(row?.binding).toBeTruthy();
    const bindingCookie = res.setCookies.find((c) => c.startsWith(`${AUTHZ_BINDING_COOKIE}=`));
    expect(bindingCookie, "the authorize 302 sets the binding cookie").toBeTruthy();
    expect(bindingCookie).toMatch(/HttpOnly/i);
    expect(bindingCookie).toMatch(/SameSite=Lax/i);
    expect(parseCookieValue(bindingCookie!, AUTHZ_BINDING_COOKIE)).toBe(row!.binding);

    // The cookie's Max-Age tracks the pending row's TTL (derived from its
    // `expiresAt`), not a stale constant — so a store with a custom `ttlMs`
    // stays in sync rather than expiring the cookie early/late.
    const maxAge = Number(/Max-Age=(\d+)/i.exec(bindingCookie!)?.[1]);
    const rowTtlSec = Math.round((row!.expiresAt - row!.createdAt) / 1000);
    expect(Math.abs(maxAge - rowTtlSec)).toBeLessThanOrEqual(5);
  });

  it("400s a non-loopback redirect_uri (the open-redirect gate)", async () => {
    const res = await h.request(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent("https://evil.com/cb")}` +
        `&code_challenge=x&code_challenge_method=S256`,
    );
    expect(res.status).toBe(400);
  });

  it("400s a missing redirect_uri", async () => {
    const res = await h.request("/auth/authorize?response_type=code&code_challenge=x");
    expect(res.status).toBe(400);
  });

  it("fails soft to the client redirect (?error=invalid_request) on a bad response_type", async () => {
    const res = await h.request(
      `/auth/authorize?response_type=token&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
        `&state=cs&code_challenge=x&code_challenge_method=S256`,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.location!);
    expect(loc.origin).toBe("http://127.0.0.1:5000");
    expect(loc.searchParams.get("error")).toBe("invalid_request");
    expect(loc.searchParams.get("state")).toBe("cs");
  });

  it("fails soft when the PKCE challenge method is not S256", async () => {
    const res = await h.request(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
        `&code_challenge=x&code_challenge_method=plain`,
    );
    expect(res.status).toBe(302);
    expect(new URL(res.location!).searchParams.get("error")).toBe("invalid_request");
  });

  it("records a single RFC 8707 resource on the pending authorization (presence never errors)", async () => {
    const res = await h.request(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
        `&code_challenge=chal&code_challenge_method=S256&resource=${encodeURIComponent("https://api.example/mcp")}`,
    );
    expect(res.status).toBe(302);
    const handle = new URLSearchParams(res.location!.split("?")[1]).get("authz")!;
    expect((await h.pending.get(handle))?.resource).toBe("https://api.example/mcp");
  });

  it("fails soft with invalid_target on a REPEATED resource param (never silently truncated)", async () => {
    const res = await h.request(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
        `&code_challenge=chal&code_challenge_method=S256&resource=a&resource=b`,
    );
    expect(res.status).toBe(302);
    expect(new URL(res.location!).searchParams.get("error")).toBe("invalid_target");
  });

  it("does not disclose WHY the trust gate rejected (client-enumeration defense)", async () => {
    // Unknown-client and bad-redirect failures must be indistinguishable.
    const badRedirect = await h.request(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent("https://evil.com/cb")}` +
        `&code_challenge=x&code_challenge_method=S256`,
    );
    expect(badRedirect.status).toBe(400);
    expect(badRedirect.body).toBe("invalid request");
  });
});

describe("AuthorizeController POST /auth/token", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await buildApp();
  });

  async function mintCode(verifier: string, tokenPolicy = { kind: "cli-session", ttl: 60_000 }) {
    const { code } = await h.codes.mint({
      userId: "u-1",
      codeChallenge: pkce(verifier),
      redirectUri: LOOPBACK,
      tokenPolicy,
    });
    return code;
  }

  it("exchanges a code + matching verifier for a working, cli-session-labelled token", async () => {
    const code = await mintCode("verifier-abc");
    const res = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code, code_verifier: "verifier-abc" }),
    );
    expect(res.status).toBe(200);
    const body = res.body as { access_token: string; token_type: string; userId: string };
    expect(body.token_type).toBe("Bearer");
    expect(body.userId).toBe("u-1");

    // The minted token actually validates …
    const ctx = await h.auth.validate(body.access_token);
    expect(ctx?.userId).toBe("u-1");
    // … and is labelled so it stays OUT of the browser session view.
    const browser = (await h.auth.listSessions("u-1")) as SessionInfo[];
    expect(browser).toHaveLength(0);
    const cli = (await h.auth.listSessions("u-1", { kind: "cli-session" })) as SessionInfo[];
    expect(cli[0]?.kind).toBe("cli-session");
  });

  it("rejects a wrong PKCE verifier with invalid_grant", async () => {
    const code = await mintCode("right-verifier");
    const res = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code, code_verifier: "wrong-verifier" }),
    );
    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects an unknown code with invalid_grant", async () => {
    const res = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code: "nope", code_verifier: "v" }),
    );
    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects a reused code (single-use) with invalid_grant", async () => {
    const code = await mintCode("v1");
    const first = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code, code_verifier: "v1" }),
    );
    expect(first.status).toBe(200);
    const second = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code, code_verifier: "v1" }),
    );
    expect(second.status).toBe(400);
    expect((second.body as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects an unsupported grant_type", async () => {
    const res = await h.request(
      "/auth/token",
      form({ grant_type: "password", code: "x", code_verifier: "y" }),
    );
    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("unsupported_grant_type");
  });

  it("rejects redeeming a loopback code with a spurious client_id (invalid_client)", async () => {
    const code = await mintCode("v-loop");
    const res = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code,
        code_verifier: "v-loop",
        client_id: "smuggled",
      }),
    );
    expect(res.status).toBe(401);
    expect((res.body as { error: string }).error).toBe("invalid_client");
  });

  it("RFC 8707: both-legs resource mismatch → invalid_target; matching or one-sided presence is fine", async () => {
    const mintWithResource = async (verifier: string) =>
      (
        await h.codes.mint({
          userId: "u-1",
          codeChallenge: pkce(verifier),
          redirectUri: LOOPBACK,
          resource: "https://api.example/mcp",
          tokenPolicy: { kind: "cli-session", ttl: 60_000 },
        })
      ).code;

    // Mismatch — the recorded grant binds the resource.
    const mismatch = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintWithResource("v1"),
        code_verifier: "v1",
        resource: "https://other.example/mcp",
      }),
    );
    expect(mismatch.status).toBe(400);
    expect((mismatch.body as { error: string }).error).toBe("invalid_target");

    // Match — accepted.
    const match = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintWithResource("v2"),
        code_verifier: "v2",
        resource: "https://api.example/mcp",
      }),
    );
    expect(match.status).toBe(200);

    // Token-leg-only presence (code recorded none) — accepted, never an error.
    const oneSided = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintCode("v3"),
        code_verifier: "v3",
        resource: "https://api.example/mcp",
      }),
    );
    expect(oneSided.status).toBe(200);
  });

  it("404s the RFC 8414 metadata + /register when neither an issuer nor DCR is wired", async () => {
    const meta = await h.request("/auth/.well-known/oauth-authorization-server");
    expect(meta.status).toBe(404);
    const reg = await h.request("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://c.example/cb"] }),
    });
    expect(reg.status).toBe(404);
  });
});

// ── Tier 2 (OIDC) — registered clients, id_token minting, discovery + JWKS ──

// One RS256 keypair for the suite — PKCS8 private + SPKI public PEM, exactly what
// IdTokenSigner consumes — generated with node:crypto so this test needs no jose.
const TEST_KEYS = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/**
 * Decode a JWT payload WITHOUT verifying the signature — the signer's full
 * sign→JWKS→verify crypto round-trip is covered in `@aooth/auth`'s
 * `id-token-signer.spec`; here we only assert the controller wired the claims.
 */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const payload = jwt.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
}

/** Emits profile claims under the granted scope (the seam the demo's resolver fills). */
class TestClaims extends OidcClaimsResolver {
  resolveClaims(userId: string, scope: string | undefined): Record<string, unknown> {
    const s = (scope ?? "").split(/\s+/u);
    const out: Record<string, unknown> = {};
    if (s.includes("email")) {
      out.email = `${userId}@example.com`;
      out.email_verified = true;
    }
    if (s.includes("profile")) out.name = "User One";
    return out;
  }
}

const ISSUER = "http://localhost/auth";

interface OidcHarness extends Harness {
  signer: IdTokenSigner;
}

async function buildOidcApp(opts?: { dcr?: boolean }): Promise<OidcHarness> {
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const http = moost.adapter(new MoostHttp(createHttpApp(undefined, new Wooks())));

  const auth = new AuthCredential({
    store: new CredentialStoreMemory(),
    method: "token",
    accessTtl: 60_000,
  });
  const pending = new PendingAuthorizationStoreMemory();
  const codes = new AuthCodeStoreMemory();
  const policy = new RegisteredClientPolicy({
    clients: [
      {
        clientId: "svc",
        redirectUris: ["https://svc.example/cb"],
        scopes: ["openid", "email", "profile"],
      },
      {
        clientId: "conf",
        redirectUris: ["https://conf.example/cb"],
        type: "confidential",
        clientSecret: "sekret-value",
        scopes: ["openid"],
      },
    ],
  });
  const signer = new IdTokenSigner({
    issuer: ISSUER,
    kid: "test-1",
    privateKey: TEST_KEYS.privateKey,
    publicKey: TEST_KEYS.publicKey,
  });

  const registration = opts?.dcr
    ? new DynamicClientRegistration({ store: new DynamicClientStoreMemory() })
    : undefined;

  // OIDC signer + claims are supplied by OVERRIDING the getters — not DI tokens
  // (an optional `@Inject` dep panics in moost's `resolveMoost` route pass).
  @Inherit()
  @Controller("auth")
  class OidcAuthorizeController extends AuthorizeController {
    constructor(
      a: AuthCredential,
      @Inject(CLIENT_REDIRECT_POLICY_TOKEN) p: ClientRedirectPolicy,
      @Inject(PENDING_AUTHORIZATION_STORE_TOKEN) pe: PendingAuthorizationStore,
      @Inject(AUTH_CODE_STORE_TOKEN) c: AuthCodeStore,
    ) {
      super(a, p, pe, c);
    }
    protected override getIdTokenSigner(): IdTokenSigner {
      return signer;
    }
    protected override getOidcClaimsResolver(): OidcClaimsResolver {
      return new TestClaims();
    }
    protected override getDynamicClientRegistration(): DynamicClientRegistration | undefined {
      return registration;
    }
  }

  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => auth],
      [CLIENT_REDIRECT_POLICY_TOKEN, () => policy],
      [PENDING_AUTHORIZATION_STORE_TOKEN, () => pending],
      [AUTH_CODE_STORE_TOKEN, () => codes],
    ),
  );
  moost.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
  // biome-ignore lint/suspicious/noExplicitAny: registerControllers' prefixed-tuple shape.
  moost.registerControllers(OidcAuthorizeController as any);
  await moost.init();

  return { request: makeRequester(http), auth, pending, codes, signer };
}

describe("AuthorizeController Tier 2 — OIDC", () => {
  let h: OidcHarness;
  beforeEach(async () => {
    h = await buildOidcApp();
  });

  it("serves OIDC discovery derived from the issuer", async () => {
    const res = await h.request("/auth/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const doc = res.body as Record<string, unknown>;
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(doc.token_endpoint).toBe(`${ISSUER}/token`);
    expect(doc.jwks_uri).toBe(`${ISSUER}/jwks`);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["RS256"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("serves the signer JWKS (public, no private material)", async () => {
    const res = await h.request("/auth/jwks");
    expect(res.status).toBe(200);
    const keys = (res.body as { keys: Record<string, unknown>[] }).keys;
    expect(keys[0].kid).toBe("test-1");
    expect(keys[0].use).toBe("sig");
    expect(keys[0].d).toBeUndefined();
  });

  it("mints an id_token an OIDC verifier accepts (sub/aud/nonce + scoped claims), no access token", async () => {
    const { code } = await h.codes.mint({
      userId: "u-1",
      codeChallenge: pkce("ver-1"),
      redirectUri: "https://svc.example/cb",
      clientId: "svc",
      audience: "svc",
      scope: "openid email profile",
      nonce: "n-123",
      idToken: true,
      accessToken: false,
      tokenPolicy: {},
    });
    const res = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code, code_verifier: "ver-1", client_id: "svc" }),
    );
    expect(res.status).toBe(200);
    const body = res.body as { id_token?: string; access_token?: string };
    expect(body.access_token).toBeUndefined(); // pure sign-in client: identity only
    expect(body.id_token).toBeDefined();

    const payload = decodeJwtPayload(body.id_token!);
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe("svc");
    expect(payload.sub).toBe("u-1");
    expect(payload.nonce).toBe("n-123");
    expect(payload.email).toBe("u-1@example.com");
    expect(payload.email_verified).toBe(true);
    expect(payload.name).toBe("User One");
  });

  it("rejects redeeming a registered code with the wrong client_id (invalid_client)", async () => {
    const { code } = await h.codes.mint({
      userId: "u-1",
      codeChallenge: pkce("v"),
      redirectUri: "https://svc.example/cb",
      clientId: "svc",
      audience: "svc",
      idToken: true,
      accessToken: false,
      tokenPolicy: {},
    });
    const res = await h.request(
      "/auth/token",
      form({ grant_type: "authorization_code", code, code_verifier: "v", client_id: "conf" }),
    );
    expect(res.status).toBe(401);
    expect((res.body as { error: string }).error).toBe("invalid_client");
  });

  it("a confidential client must present the correct secret", async () => {
    const mint = () =>
      h.codes.mint({
        userId: "u-1",
        codeChallenge: pkce("v"),
        redirectUri: "https://conf.example/cb",
        clientId: "conf",
        audience: "conf",
        scope: "openid",
        idToken: true,
        accessToken: false,
        tokenPolicy: {},
      });

    const wrong = await mint();
    const bad = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: wrong.code,
        code_verifier: "v",
        client_id: "conf",
        client_secret: "wrong",
      }),
    );
    expect(bad.status).toBe(401);
    expect((bad.body as { error: string }).error).toBe("invalid_client");

    const right = await mint();
    const ok = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: right.code,
        code_verifier: "v",
        client_id: "conf",
        client_secret: "sekret-value",
      }),
    );
    expect(ok.status).toBe(200);
    expect((ok.body as { id_token?: string }).id_token).toBeDefined();
  });

  it("serves the RFC 8414 document off the signer issuer, with jwks but WITHOUT registration_endpoint (no DCR)", async () => {
    const res = await h.request("/auth/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const doc = res.body as Record<string, unknown>;
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(doc.token_endpoint).toBe(`${ISSUER}/token`);
    expect(doc.jwks_uri).toBe(`${ISSUER}/jwks`);
    expect(doc).not.toHaveProperty("registration_endpoint");
    expect(doc.token_endpoint_auth_methods_supported).toContain("none");
    // openid-configuration stays free of registration_endpoint too.
    const oidc = await h.request("/auth/.well-known/openid-configuration");
    expect(oidc.body as object).not.toHaveProperty("registration_endpoint");
  });

  it("combined deployment (signer + DCR): BOTH discovery documents advertise registration_endpoint", async () => {
    const combined = await buildOidcApp({ dcr: true });
    const rfc8414 = await combined.request("/auth/.well-known/oauth-authorization-server");
    expect((rfc8414.body as Record<string, unknown>).registration_endpoint).toBe(
      `${ISSUER}/register`,
    );
    const oidc = await combined.request("/auth/.well-known/openid-configuration");
    expect((oidc.body as Record<string, unknown>).registration_endpoint).toBe(`${ISSUER}/register`);
    // Everything else in the OIDC doc is unchanged by the DCR wiring.
    expect((oidc.body as Record<string, unknown>).issuer).toBe(ISSUER);
    expect((oidc.body as Record<string, unknown>).jwks_uri).toBe(`${ISSUER}/jwks`);
  });
});

// ── MCP connectors (OAUTH.md) — RFC 8414 metadata without a signer, RFC 7591
//    dynamic registration, dynamic-client grant round-trip + symmetry ──

const DCR_ISSUER = "http://localhost/auth";
const DYN_REDIRECT = "https://connector.example/cb";

interface DcrHarness extends Harness {
  clients: DynamicClientStoreMemory;
}

/** Injectable clock for the refresh-grant rotation/grace tests. */
class FakeClock {
  time = 1_000_000;
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

async function buildDcrApp(opts?: {
  guard?: (args: { metadata: unknown }) => void;
  maxClients?: number;
  clock?: FakeClock;
}): Promise<DcrHarness> {
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const http = moost.adapter(new MoostHttp(createHttpApp(undefined, new Wooks())));

  const auth = new AuthCredential({
    store: new CredentialStoreMemory(opts?.clock ? { clock: opts.clock } : undefined),
    method: "token",
    accessTtl: 60_000,
    ...(opts?.clock && { clock: opts.clock }),
  });
  const pending = new PendingAuthorizationStoreMemory();
  const codes = new AuthCodeStoreMemory();
  const clients = new DynamicClientStoreMemory();
  // The OAUTH.md §6 composition: loopback CLI + dynamic connectors, NO static
  // registry — `registered` is optional on the composite now.
  const policy = new CompositeClientPolicy({
    loopback: new LoopbackClientPolicy(),
    dynamic: new DynamicClientPolicy({
      store: clients,
      tokenPolicy: { kind: "mcp-session", ttl: 30 * 24 * 60 * 60_000 },
      allowedScopes: ["read", "write"],
    }),
  });
  const registration = new DynamicClientRegistration({
    store: clients,
    ...(opts?.maxClients !== undefined && { maxClients: opts.maxClients }),
    ...(opts?.guard && { guard: opts.guard }),
  });

  // SIGNER-LESS deployment (the R1 acceptance case): no IdTokenSigner override —
  // only `getIssuer()` + the registration getter.
  @Inherit()
  @Controller("auth")
  class DcrAuthorizeController extends AuthorizeController {
    constructor(
      a: AuthCredential,
      @Inject(CLIENT_REDIRECT_POLICY_TOKEN) p: ClientRedirectPolicy,
      @Inject(PENDING_AUTHORIZATION_STORE_TOKEN) pe: PendingAuthorizationStore,
      @Inject(AUTH_CODE_STORE_TOKEN) c: AuthCodeStore,
    ) {
      super(a, p, pe, c);
    }
    protected override getIssuer(): string {
      return DCR_ISSUER;
    }
    protected override getDynamicClientRegistration(): DynamicClientRegistration {
      return registration;
    }
    protected override scopesSupported(): string[] {
      return ["read", "write"];
    }
  }

  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => auth],
      [CLIENT_REDIRECT_POLICY_TOKEN, () => policy],
      [PENDING_AUTHORIZATION_STORE_TOKEN, () => pending],
      [AUTH_CODE_STORE_TOKEN, () => codes],
    ),
  );
  moost.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
  // biome-ignore lint/suspicious/noExplicitAny: registerControllers' prefixed-tuple shape.
  moost.registerControllers(DcrAuthorizeController as any);
  await moost.init();

  return { request: makeRequester(http), auth, pending, codes, clients };
}

const registerJson = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

describe("AuthorizeController — MCP connectors (RFC 8414 + RFC 7591 + dynamic grant)", () => {
  let h: DcrHarness;
  beforeEach(async () => {
    h = await buildDcrApp();
  });

  it("serves RFC 8414 metadata with NO signer configured (the R1 core case)", async () => {
    const res = await h.request("/auth/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const doc = res.body as Record<string, unknown>;
    expect(doc.issuer).toBe(DCR_ISSUER);
    expect(doc.authorization_endpoint).toBe(`${DCR_ISSUER}/authorize`);
    expect(doc.token_endpoint).toBe(`${DCR_ISSUER}/token`);
    expect(doc.registration_endpoint).toBe(`${DCR_ISSUER}/register`);
    expect(doc.response_types_supported).toEqual(["code"]);
    expect(doc.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.token_endpoint_auth_methods_supported).toContain("none");
    expect(doc.scopes_supported).toEqual(["read", "write"]);
    expect(doc).not.toHaveProperty("jwks_uri"); // no signer ⇒ no JWKS
    // The OIDC discovery stays signer-gated: 404 here.
    const oidc = await h.request("/auth/.well-known/openid-configuration");
    expect(oidc.status).toBe(404);
  });

  it("DCR round-trip: 201 with client_id, issued_at in SECONDS, narrowed echo, no secret fields for a public client", async () => {
    const res = await h.request(
      "/auth/register",
      registerJson({
        client_name: "Test Connector",
        redirect_uris: [DYN_REDIRECT],
        token_endpoint_auth_method: "none",
        // The connector's refresh_token ask registers with it echoed; an
        // unsupported grant is narrowed away (RFC 7591 §2 — the echo of the
        // narrowed set is the contract).
        grant_types: ["authorization_code", "refresh_token", "client_credentials"],
        response_types: ["code"],
        scope: "read write",
      }),
    );
    expect(res.status).toBe(201);
    const body = res.body as Record<string, unknown>;
    expect(body.client_id).toBeTruthy();
    expect(body.client_id_issued_at).toBeLessThan(Date.now() / 100); // seconds, not ms
    expect(body.redirect_uris).toEqual([DYN_REDIRECT]);
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
    expect(body.response_types).toEqual(["code"]);
    expect(body.client_name).toBe("Test Connector");
    expect(body).not.toHaveProperty("client_secret");
    expect(body).not.toHaveProperty("client_secret_expires_at");
    expect(await h.clients.get(body.client_id as string)).not.toBeNull();
  });

  it("confidential DCR (the claude.ai payload): client_secret_post registers 201 with a one-time secret; only the hash is stored", async () => {
    // Verbatim claude.ai connector-platform registration shape (REFRESH_TOKEN.md §1a).
    const res = await h.request(
      "/auth/register",
      registerJson({
        redirect_uris: [DYN_REDIRECT],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Claude",
        application_type: "web", // unknown field — ignored, never echoed
      }),
    );
    expect(res.status).toBe(201);
    const body = res.body as Record<string, unknown>;
    expect(body.token_endpoint_auth_method).toBe("client_secret_post");
    expect(body.client_secret).toMatch(/^[\w-]{43}$/u); // 32 bytes base64url
    expect(body.client_secret_expires_at).toBe(0); // §3.2.1: 0 ⇒ never expires
    expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
    expect(body).not.toHaveProperty("application_type");
    // The store holds a digest, never the plaintext.
    const stored = await h.clients.get(body.client_id as string);
    expect(stored?.clientSecretHash).toBe(hashClientSecret(body.client_secret as string));
    expect(JSON.stringify(stored)).not.toContain(body.client_secret as string);
  });

  it("a confidential dynamic code redeems only WITH the minted secret (client_secret_post at /token)", async () => {
    const reg = await h.request(
      "/auth/register",
      registerJson({
        redirect_uris: [DYN_REDIRECT],
        token_endpoint_auth_method: "client_secret_post",
      }),
    );
    const { client_id, client_secret } = reg.body as { client_id: string; client_secret: string };
    const client = (await h.clients.get(client_id))!;

    const denied = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintDynamicCode(client, "v-conf-1"),
        code_verifier: "v-conf-1",
        client_id,
      }),
    );
    expect(denied.status).toBe(401);
    expect((denied.body as { error: string }).error).toBe("invalid_client");

    const wrong = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintDynamicCode(client, "v-conf-2"),
        code_verifier: "v-conf-2",
        client_id,
        client_secret: "wrong",
      }),
    );
    expect(wrong.status).toBe(401);

    const ok = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintDynamicCode(client, "v-conf-3"),
        code_verifier: "v-conf-3",
        client_id,
        client_secret,
      }),
    );
    expect(ok.status).toBe(200);
    const ctx = await h.auth.validate((ok.body as { access_token: string }).access_token);
    expect(ctx?.userId).toBe("u-1");
  });

  it("rejects non-JSON registration requests and RFC 7591 metadata violations with the 7591 error shape", async () => {
    const formEncoded = await h.request("/auth/register", form({ redirect_uris: DYN_REDIRECT }));
    expect(formEncoded.status).toBe(400);
    expect((formEncoded.body as { error: string }).error).toBe("invalid_client_metadata");

    const badRedirect = await h.request(
      "/auth/register",
      registerJson({ redirect_uris: ["myapp://callback"] }),
    );
    expect(badRedirect.status).toBe(400);
    const err = badRedirect.body as { error: string; error_description?: string };
    expect(err.error).toBe("invalid_redirect_uri");
    expect(err.error_description).toBeTruthy();

    const wantsSecret = await h.request(
      "/auth/register",
      registerJson({
        redirect_uris: [DYN_REDIRECT],
        token_endpoint_auth_method: "client_secret_basic",
      }),
    );
    expect(wantsSecret.status).toBe(400);
    expect((wantsSecret.body as { error: string }).error).toBe("invalid_client_metadata");
  });

  it("guard rejections surface as 7591 errors; the cap rejects-when-full", async () => {
    const guarded = await buildDcrApp({
      guard: () => {
        throw new ClientRegistrationError("invalid_client_metadata", "not today");
      },
    });
    const denied = await guarded.request(
      "/auth/register",
      registerJson({ redirect_uris: [DYN_REDIRECT] }),
    );
    expect(denied.status).toBe(400);
    expect(denied.body).toEqual({
      error: "invalid_client_metadata",
      error_description: "not today",
    });

    const capped = await buildDcrApp({ maxClients: 1 });
    const first = await capped.request(
      "/auth/register",
      registerJson({ redirect_uris: [DYN_REDIRECT] }),
    );
    expect(first.status).toBe(201);
    const second = await capped.request(
      "/auth/register",
      registerJson({ redirect_uris: [DYN_REDIRECT] }),
    );
    expect(second.status).toBe(400);
    expect((second.body as { error: string }).error).toBe("invalid_client_metadata");
  });

  async function registerClient(): Promise<DynamicClient> {
    const res = await h.request(
      "/auth/register",
      registerJson({
        client_name: "Test Connector",
        redirect_uris: [DYN_REDIRECT],
        scope: "read write",
      }),
    );
    expect(res.status).toBe(201);
    return (await h.clients.get((res.body as { client_id: string }).client_id))!;
  }

  it("dynamic authorize: pending row records clientId + clientName + resource; scope is allow-list-bounded", async () => {
    const client = await registerClient();
    const res = await h.request(
      `/auth/authorize?response_type=code&client_id=${client.clientId}` +
        `&redirect_uri=${encodeURIComponent(DYN_REDIRECT)}&state=cs` +
        `&code_challenge=chal&code_challenge_method=S256&scope=${encodeURIComponent("read admin")}` +
        `&resource=${encodeURIComponent("https://api.example/mcp")}`,
    );
    expect(res.status).toBe(302);
    expect(res.location).toMatch(/^\/login\?authz=/);
    const handle = new URLSearchParams(res.location!.split("?")[1]).get("authz")!;
    const row = await h.pending.get(handle);
    expect(row?.clientId).toBe(client.clientId);
    expect(row?.clientName).toBe("Test Connector"); // consent display, snapshot here
    expect(row?.resource).toBe("https://api.example/mcp");
    expect(row?.scope).toBe("read"); // requested ∩ allowedScopes ∩ registration
    expect(row?.tokenPolicy.kind).toBe("mcp-session");
  });

  it("an unregistered redirect_uri for a dynamic client is a benign 400, never a redirect", async () => {
    const client = await registerClient();
    const res = await h.request(
      `/auth/authorize?response_type=code&client_id=${client.clientId}` +
        `&redirect_uri=${encodeURIComponent("https://evil.example/cb")}` +
        `&code_challenge=x&code_challenge_method=S256`,
    );
    expect(res.status).toBe(400);
    expect(res.location).toBeNull();
    expect(res.body).toBe("invalid request");
  });

  async function mintDynamicCode(
    client: DynamicClient,
    verifier: string,
    extra: { resource?: string } = {},
  ): Promise<string> {
    const { code } = await h.codes.mint({
      userId: "u-1",
      codeChallenge: pkce(verifier),
      redirectUri: DYN_REDIRECT,
      clientId: client.clientId,
      scope: "read",
      ...(extra.resource !== undefined && { resource: extra.resource }),
      tokenPolicy: { kind: "mcp-session", ttl: 30 * 24 * 60 * 60_000 },
    });
    return code;
  }

  it("redeems a dynamic code with client_id + verifier (+ matching resource) for a working mcp-session token", async () => {
    const client = await registerClient();
    const code = await mintDynamicCode(client, "ver-dyn", {
      resource: "https://api.example/mcp",
    });
    const res = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code,
        code_verifier: "ver-dyn",
        client_id: client.clientId,
        resource: "https://api.example/mcp",
      }),
    );
    expect(res.status).toBe(200);
    const body = res.body as { access_token: string; id_token?: string };
    expect(body.id_token).toBeUndefined(); // NO id_token for dynamic clients (v1)
    const ctx = await h.auth.validate(body.access_token);
    expect(ctx?.userId).toBe("u-1");
    const sessions = (await h.auth.listSessions("u-1", { kind: "mcp-session" })) as SessionInfo[];
    expect(sessions[0]?.kind).toBe("mcp-session");
  });

  it("SYMMETRY: a dynamic code without client_id, or with another client's id, is 401 invalid_client", async () => {
    const client = await registerClient();

    const missing = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintDynamicCode(client, "v1"),
        code_verifier: "v1",
      }),
    );
    expect(missing.status).toBe(401);
    expect((missing.body as { error: string }).error).toBe("invalid_client");

    const other = await registerClient();
    const swapped = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code: await mintDynamicCode(client, "v2"),
        code_verifier: "v2",
        client_id: other.clientId,
      }),
    );
    expect(swapped.status).toBe(401);
    expect((swapped.body as { error: string }).error).toBe("invalid_client");
  });

  it("fails closed when the registration was deleted between authorize and redemption (GC race)", async () => {
    const client = await registerClient();
    const code = await mintDynamicCode(client, "v-gone");
    await h.clients.delete(client.clientId);
    const res = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code,
        code_verifier: "v-gone",
        client_id: client.clientId,
      }),
    );
    expect(res.status).toBe(401);
    expect((res.body as { error: string }).error).toBe("invalid_client");
  });
});

// ── refresh_token grant (OAuth 2.1 §4.3) — mint on code redemption (opt-in per
//    TokenPolicy), rotate on redemption, family revocation on replay ──

describe("AuthorizeController — refresh_token grant", () => {
  let h: DcrHarness;
  let clock: FakeClock;
  beforeEach(async () => {
    clock = new FakeClock();
    h = await buildDcrApp({ clock });
  });

  async function registerClient(): Promise<DynamicClient> {
    const res = await h.request(
      "/auth/register",
      registerJson({ client_name: "Refresh Connector", redirect_uris: [DYN_REDIRECT] }),
    );
    expect(res.status).toBe(201);
    return (await h.clients.get((res.body as { client_id: string }).client_id))!;
  }

  /** Mint a code whose policy opts into refresh (unless `refresh` is null). */
  async function mintCode(
    client: DynamicClient | undefined,
    verifier: string,
    refresh: { ttl?: number } | null = { ttl: 100_000 },
  ): Promise<string> {
    const { code } = await h.codes.mint({
      userId: "u-1",
      codeChallenge: pkce(verifier),
      redirectUri: client ? DYN_REDIRECT : LOOPBACK,
      ...(client && { clientId: client.clientId }),
      tokenPolicy: {
        kind: "mcp-session",
        ttl: 60_000,
        ...(refresh !== null && { refresh }),
      },
    });
    return code;
  }

  async function redeemCode(client: DynamicClient | undefined, verifier: string, code: string) {
    const res = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        ...(client && { client_id: client.clientId }),
      }),
    );
    expect(res.status).toBe(200);
    return res.body as { access_token: string; refresh_token?: string };
  }

  it("policy.refresh mints a refresh_token on code redemption; a policy WITHOUT it behaves exactly as today", async () => {
    const client = await registerClient();

    const withRefresh = await redeemCode(client, "v-r1", await mintCode(client, "v-r1"));
    expect(withRefresh.refresh_token).toBeTruthy();
    expect(await h.auth.validate(withRefresh.access_token)).toMatchObject({ userId: "u-1" });

    // Policy-off: no refresh_token even though the client registered the grant.
    const without = await redeemCode(client, "v-r2", await mintCode(client, "v-r2", null));
    expect(without.refresh_token).toBeUndefined();
  });

  it("a clientless (loopback) grant IGNORES policy.refresh — nothing to bind the family to", async () => {
    const body = await redeemCode(undefined, "v-loop", await mintCode(undefined, "v-loop"));
    expect(body.refresh_token).toBeUndefined();
    expect(await h.auth.validate(body.access_token)).toMatchObject({ userId: "u-1" });
  });

  it("redeems grant_type=refresh_token with rotation; the grant's authority (kind, per-mint ttl) rides the family", async () => {
    const client = await registerClient();
    const first = await redeemCode(client, "v-rot", await mintCode(client, "v-rot"));

    clock.advance(5_000);
    const res = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token!,
        client_id: client.clientId,
      }),
    );
    expect(res.status).toBe(200);
    const body = res.body as {
      token_type: string;
      access_token: string;
      refresh_token?: string;
      userId: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.userId).toBe("u-1");
    expect(body.refresh_token).toBeTruthy();
    expect(body.refresh_token).not.toBe(first.refresh_token);

    const ctx = await h.auth.validate(body.access_token);
    expect(ctx?.userId).toBe("u-1");
    // Authority fixed at authorize time: the policy's 60s access ttl (stamped
    // as metadata.accessTtl), never the instance default.
    expect(ctx?.expiresAt).toBe(clock.now() + 60_000);
    const sessions = (await h.auth.listSessions("u-1", { kind: "mcp-session" })) as SessionInfo[];
    expect(sessions[0]?.kind).toBe("mcp-session");
  });

  it("replaying a rotated refresh token beyond grace revokes the whole family (theft response)", async () => {
    const client = await registerClient();
    const first = await redeemCode(client, "v-theft", await mintCode(client, "v-theft"));

    const rotated = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token!,
        client_id: client.clientId,
      }),
    );
    expect(rotated.status).toBe(200);
    const fresh = rotated.body as { access_token: string; refresh_token: string };

    clock.advance(31_000); // beyond the 30s rotation grace
    const replay = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token!,
        client_id: client.clientId,
      }),
    );
    expect(replay.status).toBe(400);
    expect((replay.body as { error: string }).error).toBe("invalid_grant");
    // The whole family died with it — rotated access AND refresh included.
    expect(await h.auth.validate(fresh.access_token)).toBeNull();
    const reuse = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: fresh.refresh_token,
        client_id: client.clientId,
      }),
    );
    expect(reuse.status).toBe(400);
    expect((reuse.body as { error: string }).error).toBe("invalid_grant");
  });

  it("client binding: another client's id ⇒ invalid_grant; unknown client ⇒ invalid_client; missing params rejected", async () => {
    const client = await registerClient();
    const other = await registerClient();
    const first = await redeemCode(client, "v-bind", await mintCode(client, "v-bind"));

    const swapped = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token!,
        client_id: other.clientId,
      }),
    );
    expect(swapped.status).toBe(400);
    expect((swapped.body as { error: string }).error).toBe("invalid_grant");
    // The mismatch left the family untouched — the rightful client still refreshes.
    const rightful = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token!,
        client_id: client.clientId,
      }),
    );
    expect(rightful.status).toBe(200);

    const unknown = await h.request(
      "/auth/token",
      form({ grant_type: "refresh_token", refresh_token: "whatever", client_id: "nope" }),
    );
    expect(unknown.status).toBe(401);
    expect((unknown.body as { error: string }).error).toBe("invalid_client");

    const noClient = await h.request(
      "/auth/token",
      form({ grant_type: "refresh_token", refresh_token: first.refresh_token! }),
    );
    expect(noClient.status).toBe(401);
    expect((noClient.body as { error: string }).error).toBe("invalid_client");

    const noToken = await h.request(
      "/auth/token",
      form({ grant_type: "refresh_token", client_id: client.clientId }),
    );
    expect(noToken.status).toBe(400);
    expect((noToken.body as { error: string }).error).toBe("invalid_request");
  });

  it("a session-tier refresh token (no authz stamp) is NOT redeemable at the OAuth token endpoint", async () => {
    const client = await registerClient();
    // Minted by the session tier directly — no metadata.authzClientId.
    const session = await h.auth.issue("u-1", { refresh: { ttl: 100_000 } });
    const res = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: session.refreshToken!,
        client_id: client.clientId,
      }),
    );
    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("invalid_grant");
    // And it was NOT rotated/revoked by the attempt.
    const still = await h.auth.refresh(session.refreshToken!);
    expect(still.accessToken).toBeTruthy();
  });

  it("a confidential client must authenticate to refresh (client_secret_post)", async () => {
    const reg = await h.request(
      "/auth/register",
      registerJson({
        redirect_uris: [DYN_REDIRECT],
        token_endpoint_auth_method: "client_secret_post",
      }),
    );
    const { client_id, client_secret } = reg.body as { client_id: string; client_secret: string };
    const client = (await h.clients.get(client_id))!;

    const code = await mintCode(client, "v-conf-r");
    const first = await h.request(
      "/auth/token",
      form({
        grant_type: "authorization_code",
        code,
        code_verifier: "v-conf-r",
        client_id,
        client_secret,
      }),
    );
    expect(first.status).toBe(200);
    const refreshToken = (first.body as { refresh_token: string }).refresh_token;
    expect(refreshToken).toBeTruthy();

    const noSecret = await h.request(
      "/auth/token",
      form({ grant_type: "refresh_token", refresh_token: refreshToken, client_id }),
    );
    expect(noSecret.status).toBe(401);
    expect((noSecret.body as { error: string }).error).toBe("invalid_client");

    const ok = await h.request(
      "/auth/token",
      form({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id,
        client_secret,
      }),
    );
    expect(ok.status).toBe(200);
    expect((ok.body as { refresh_token?: string }).refresh_token).toBeTruthy();
  });

  it("unknown grant_type still answers unsupported_grant_type", async () => {
    const res = await h.request("/auth/token", form({ grant_type: "client_credentials" }));
    expect(res.status).toBe(400);
    expect((res.body as { error: string }).error).toBe("unsupported_grant_type");
  });
});
