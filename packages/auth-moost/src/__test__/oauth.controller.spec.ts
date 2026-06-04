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

import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { FakeIdentityProvider, OAuthProviderRegistry, verifyState } from "@aooth/idp";
import { FederatedIdentityStoreMemory, UserService, UserStoreMemory } from "@aooth/user";
import { MoostHttp } from "@moostjs/event-http";
import { createHttpApp } from "@wooksjs/event-http";
import { createProvideRegistry, getMoostInfact, Moost } from "moost";
import { Wooks } from "wooks";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { authGuardInterceptor } from "../auth.guard";
import { OAUTH_CSRF_COOKIE } from "../oauth/oauth-csrf";
import { OAuthController } from "../oauth/oauth.controller";
import { FEDERATED_IDENTITY_STORE_TOKEN } from "../oauth/oauth-tokens";

const STATE_SECRET = "test-oauth-state-secret-0123456789";

interface Harness {
  request: (
    input: string,
    init?: RequestInit,
  ) => Promise<{ status: number; body: unknown; location: string | null; setCookies: string[] }>;
  registry: OAuthProviderRegistry;
  federated: FederatedIdentityStoreMemory;
  auth: AuthCredential;
  users: UserService;
}

async function buildApp(): Promise<Harness> {
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const http = moost.adapter(new MoostHttp(createHttpApp(undefined, new Wooks())));

  const auth = new AuthCredential({
    store: new CredentialStoreMemory(),
    method: "token",
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "always" },
  });
  const users = new UserService(new UserStoreMemory());
  const registry = new OAuthProviderRegistry({
    baseUrl: "https://app.test",
    stateSecret: STATE_SECRET,
    providers: [new FakeIdentityProvider({ id: "google" })],
    policy: { allowSignup: true, trustEmailVerifiedFrom: ["google"] },
  });
  const federated = new FederatedIdentityStoreMemory();

  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => auth],
      [UserService, () => users],
      [OAuthProviderRegistry, () => registry],
      // Abstract store binds under an explicit string token (see oauth-tokens.ts).
      [FEDERATED_IDENTITY_STORE_TOKEN, () => federated],
    ),
  );
  moost.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
  // biome-ignore lint/suspicious/noExplicitAny: registerControllers' prefixed-tuple shape.
  moost.registerControllers(OAuthController as any);
  await moost.init();

  async function request(input: string, init: RequestInit = {}) {
    // `redirect: 'manual'` is irrelevant to MoostHttp.request (it returns the
    // raw 302), but keep the helper shape close to fetch.
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
      setCookies: response.headers.getSetCookie?.() ?? [],
    };
  }

  return { request, registry, federated, auth, users };
}

/** Verify + decode the signed `state` carried in a 302 Location URL. */
async function statePayloadFromLocation(location: string) {
  const state = new URL(location).searchParams.get("state");
  expect(state, "Location carries a signed state").toBeTruthy();
  return verifyState(state!, STATE_SECRET);
}

function csrfCookieValue(setCookies: string[]): string | null {
  const c = setCookies.find((s) => s.startsWith(`${OAUTH_CSRF_COOKIE}=`));
  if (!c) return null;
  return c.slice(`${OAUTH_CSRF_COOKIE}=`.length).split(";")[0] ?? null;
}

const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

// Anonymous LOGIN is no longer a controller route — it lives in `auth/login/flow`
// (`AuthWorkflow.beginSso`). The controller now serves only the authenticated
// account-management routes: `/:provider/link` and `DELETE /:provider/:subject`.
describe("OAuthController /:provider/link", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await buildApp();
  });

  it("401s an anonymous caller", async () => {
    const res = await h.request("/auth/oauth/google/link");
    expect(res.status).toBe(401);
  });

  it("404s an unknown provider (authenticated)", async () => {
    const issued = await h.auth.issue("user-42");
    const res = await h.request("/auth/oauth/github/link", bearer(issued.accessToken));
    expect(res.status).toBe(404);
  });

  it("302s to the provider with a signed state, derived PKCE challenge, and a Lax CSRF cookie", async () => {
    const issued = await h.auth.issue("user-42");
    const res = await h.request(
      "/auth/oauth/google/link?redirect=/dashboard",
      bearer(issued.accessToken),
    );
    expect(res.status).toBe(302);
    expect(res.location).toBeTruthy();
    const url = new URL(res.location!);
    expect(url.origin + url.pathname).toBe("https://fake-idp.test/authorize");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://app.test/auth/oauth/google/callback",
    );

    // CSRF cookie is set, Lax + httpOnly, and equals the signed state's `random` seed.
    const cookie = res.setCookies.find((s) => s.startsWith(`${OAUTH_CSRF_COOKIE}=`));
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);

    const payload = await statePayloadFromLocation(res.location!);
    expect(payload.provider).toBe("google");
    expect(payload.redirect).toBe("/dashboard");
    expect(csrfCookieValue(res.setCookies)).toBe(payload.random);
    // `userId` is bound in the SIGNED state (HS256, tamper-proof) — the callback
    // links the verified identity to this user.
    expect(payload.userId).toBe("user-42");
    // STATELESS: the verifier is never in the URL/state — it is re-derived from
    // the seed. The challenge in the URL must match the derived verifier's.
    expect(payload.verifier).toBeUndefined();
    expect(url.searchParams.get("code_challenge")).toBe(
      h.registry.deriveSeededPkce(payload.random).challenge,
    );
  });

  it("falls back to '/' for an open-redirect target", async () => {
    const issued = await h.auth.issue("user-42");
    const res = await h.request(
      "/auth/oauth/google/link?redirect=https://evil.test",
      bearer(issued.accessToken),
    );
    const payload = await statePayloadFromLocation(res.location!);
    expect(payload.redirect).toBe("/");
  });
});

describe("OAuthController unlink", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await buildApp();
  });

  it("401s an anonymous caller", async () => {
    const res = await h.request("/auth/oauth/google/sub-1", { method: "DELETE" });
    expect(res.status).toBe(401);
  });

  it("404s an identity the user does not own", async () => {
    const issued = await h.auth.issue("user-1");
    await h.federated.link({ provider: "google", subject: "sub-other", userId: "user-2" });
    const res = await h.request("/auth/oauth/google/sub-other", {
      method: "DELETE",
      ...bearer(issued.accessToken),
    });
    expect(res.status).toBe(404);
  });

  it("409s when it is the user's only sign-in method (no password, no other identity)", async () => {
    const user = await h.users.createUser("solo@test"); // createUser → password.isInitial = true
    await h.federated.link({ provider: "google", subject: "sub-solo", userId: user.id });
    const issued = await h.auth.issue(user.id);
    const res = await h.request("/auth/oauth/google/sub-solo", {
      method: "DELETE",
      ...bearer(issued.accessToken),
    });
    expect(res.status).toBe(409);
    // Still linked — the guard refused.
    expect(await h.federated.find("google", "sub-solo")).not.toBeNull();
  });

  it("unlinks and revokes sessions when another identity remains", async () => {
    const user = await h.users.createUser("multi@test");
    await h.federated.link({ provider: "google", subject: "sub-a", userId: user.id });
    await h.federated.link({ provider: "github", subject: "sub-b", userId: user.id });
    const issued = await h.auth.issue(user.id);

    const res = await h.request("/auth/oauth/google/sub-a", {
      method: "DELETE",
      ...bearer(issued.accessToken),
    });
    // moost defaults a body-returning DELETE to 202 (same as the shipped
    // `SessionsController.revokeSession`).
    expect(res.status).toBe(202);
    expect(res.body).toEqual({ ok: true });
    expect(await h.federated.find("google", "sub-a")).toBeNull();
    expect(await h.federated.find("github", "sub-b")).not.toBeNull();
    // Sessions revoked — the previously-issued access token no longer validates.
    expect(await h.auth.validate(issued.accessToken)).toBeNull();
  });
});

describe("OAuthController identities (connected accounts)", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await buildApp();
  });

  it("401s an anonymous caller", async () => {
    const res = await h.request("/auth/oauth/identities");
    expect(res.status).toBe(401);
  });

  it("returns an empty list when the user has no linked identities", async () => {
    const issued = await h.auth.issue("user-1");
    const res = await h.request("/auth/oauth/identities", bearer(issued.accessToken));
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it("lists ONLY the caller's identities, projected (no id/userId), keyed by (provider, subject)", async () => {
    await h.federated.link({
      provider: "google",
      subject: "sub-mine",
      userId: "user-1",
      email: "me@test",
      displayName: "Me",
    });
    // A different user's link must NOT leak into the caller's list.
    await h.federated.link({ provider: "github", subject: "sub-other", userId: "user-2" });
    const issued = await h.auth.issue("user-1");
    const res = await h.request("/auth/oauth/identities", bearer(issued.accessToken));

    expect(res.status).toBe(200);
    const list = res.body as Array<Record<string, unknown>>;
    expect(list).toHaveLength(1);
    const row = list[0];
    expect(row.provider).toBe("google");
    expect(row.subject).toBe("sub-mine");
    expect(row.email).toBe("me@test");
    expect(row.displayName).toBe("Me");
    expect(typeof row.linkedAt).toBe("number");
    // Projection drops the surrogate `id` and the (caller's own) `userId`.
    expect(row).not.toHaveProperty("id");
    expect(row).not.toHaveProperty("userId");
  });
});
