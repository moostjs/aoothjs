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

async function buildOidcApp(): Promise<OidcHarness> {
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
});
