/**
 * MCP-connector onboarding e2e (OAUTH.md) — the full discovery → registration →
 * grant → resource chain a connector-style client (claude.ai-like: cannot set
 * headers, can only follow OAuth) walks, end-to-end over HTTP:
 *
 *   POST /mcp with no token → 401 + `WWW-Authenticate: Bearer
 *     resource_metadata="…"` → GET the RFC 9728 PRM at the SERVER ROOT →
 *     `authorization_servers[0]` → GET the RFC 8414 AS metadata (BOTH the
 *     controller-mounted suffix form and the root path-insertion form — same
 *     issuer, byte-equal documents) → POST {issuer}/register (RFC 7591; the
 *     refresh_token ask is echoed, an unsupported grant is narrowed) → browser:
 *     GET /auth/authorize (client_id + PKCE + resource) → /login?authz= →
 *     password login → consent NAMES the client + its redirect host →
 *     302 ?code&state → POST /auth/token (client_id + verifier + resource) →
 *     the minted mcp-session bearer unlocks POST /mcp → at "expiry" the
 *     connector silently POSTs grant_type=refresh_token and the ROTATED pair
 *     keeps /mcp unlocked with no browser round.
 *
 * A confidential variant registers with token_endpoint_auth_method
 * "client_secret_post" (the claude.ai shape) — the minted client_secret is
 * disclosed once and REQUIRED on both token-endpoint grants.
 *
 * Negatives pin the symmetric client binding (a dynamic code without its
 * client_id is 401) and the RFC 8707 consistency check (mismatched resource
 * between the legs is invalid_target).
 */
import { createHash, randomBytes } from "node:crypto";

import { expect, test } from "@playwright/test";

import { fillField, resetApp, submitForm, USERS, waitForConsent } from "./harness";

const b64url = (b: Buffer): string => b.toString("base64url");

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

// The connector's redirect target. An https host would be exact-matched the
// same way; the loopback literal keeps the e2e self-contained (and exercises
// the RFC 8252 port-agnostic loopback matching at /authorize is NOT needed —
// the registered port is used verbatim).
const CONNECTOR_NAME = "Claude (test connector)";

interface RegisteredConnector {
  clientId: string;
  redirectUri: string;
  clientSecret?: string;
}

async function discoverAndRegister(
  request: import("@playwright/test").APIRequestContext,
  origin: string,
  authMethod: "none" | "client_secret_post" = "none",
): Promise<RegisteredConnector> {
  // 1. Unauthenticated probe → 401 + the RFC 9728 §5.1 challenge.
  const probe = await request.post(`${origin}/mcp`, { failOnStatusCode: false });
  expect(probe.status()).toBe(401);
  const challenge = probe.headers()["www-authenticate"] ?? "";
  const prmUrl = /resource_metadata="([^"]+)"/u.exec(challenge)?.[1];
  expect(prmUrl, "the 401 challenge points at the PRM").toBeTruthy();

  // 2. PRM at the server root → the authorization server's issuer.
  const prm = (await (await request.get(prmUrl!)).json()) as {
    resource: string;
    authorization_servers: string[];
  };
  expect(prm.resource).toBe(`${origin}/mcp`);
  const issuer = prm.authorization_servers[0];
  expect(issuer).toBe(`${origin}/auth`);

  // 3. RFC 8414 metadata — the suffix form under the issuer AND the
  //    path-insertion form at the root must be byte-equal (same builder).
  const suffixDoc = (await (
    await request.get(`${issuer}/.well-known/oauth-authorization-server`)
  ).json()) as Record<string, unknown>;
  const rootDoc = (await (
    await request.get(`${origin}/.well-known/oauth-authorization-server/auth`)
  ).json()) as Record<string, unknown>;
  expect(suffixDoc.issuer).toBe(issuer);
  expect(rootDoc).toEqual(suffixDoc);
  expect(suffixDoc.registration_endpoint).toBe(`${issuer}/register`);
  expect(suffixDoc.code_challenge_methods_supported).toEqual(["S256"]);
  expect(suffixDoc.token_endpoint_auth_methods_supported).toContain("none");

  // 4. RFC 7591 dynamic registration — the connector's refresh_token ask is
  //    echoed (the grant is supported); an unsupported grant would be narrowed
  //    away, and the 201 echo of the narrowed set is the contract.
  const redirectUri = `${origin}/__test/oidc-callback`;
  const reg = await request.post(suffixDoc.registration_endpoint as string, {
    data: {
      client_name: CONNECTOR_NAME,
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: authMethod,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "read write",
    },
  });
  expect(reg.status()).toBe(201);
  const body = (await reg.json()) as Record<string, unknown>;
  expect(body.client_id).toBeTruthy();
  expect(body.grant_types, "the refresh_token ask is registered and echoed").toEqual([
    "authorization_code",
    "refresh_token",
  ]);
  expect(body.token_endpoint_auth_method).toBe(authMethod);
  if (authMethod === "none") {
    expect(body, "public client: no secret fields").not.toHaveProperty("client_secret");
  } else {
    expect(body.client_secret, "confidential client: the ONE secret disclosure").toBeTruthy();
    expect(body.client_secret_expires_at).toBe(0);
  }

  return {
    clientId: body.client_id as string,
    redirectUri,
    ...(typeof body.client_secret === "string" && { clientSecret: body.client_secret }),
  };
}

/** Run the browser leg (login + consent) and return the delivered code + verifier. */
async function mintCodeViaBrowser(
  page: import("@playwright/test").Page,
  origin: string,
  connector: RegisteredConnector,
): Promise<{ code: string; codeVerifier: string }> {
  const codeVerifier = b64url(randomBytes(32));
  const codeChallenge = b64url(createHash("sha256").update(codeVerifier).digest());
  await page.goto(
    `${origin}/auth/authorize?response_type=code&client_id=${connector.clientId}` +
      `&redirect_uri=${encodeURIComponent(connector.redirectUri)}` +
      `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(`${origin}/mcp`)}`,
  );
  await fillField(page, "username", USERS.alice.username);
  await fillField(page, "password", USERS.alice.password);
  await submitForm(page);
  await waitForConsent(page);
  await submitForm(page);
  await page.waitForURL(/\/__test\/oidc-callback\?/u, { timeout: 15_000 });
  return { code: new URL(page.url()).searchParams.get("code")!, codeVerifier };
}

test("AUTHZ-DCR-01: full connector flow — discovery → register → consent names the client → token unlocks /mcp", async ({
  page,
  request,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  const { clientId, redirectUri } = await discoverAndRegister(request, origin);

  // 5. Authorization-code + PKCE in the user's browser, with the RFC 8707
  //    resource indicator on the authorize leg.
  const codeVerifier = b64url(randomBytes(32));
  const codeChallenge = b64url(createHash("sha256").update(codeVerifier).digest());
  const state = b64url(randomBytes(16));
  const resource = `${origin}/mcp`;

  await page.goto(
    `${origin}/auth/authorize?response_type=code&client_id=${clientId}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent("read write")}&state=${state}` +
      `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(resource)}`,
  );
  await fillField(page, "username", USERS.alice.username);
  await fillField(page, "password", USERS.alice.password);
  await submitForm(page);

  // 6. The consent prompt names the DCR client AND its validated redirect host
  //    (R5) — the registrant-chosen name never stands alone.
  await waitForConsent(page);
  const notice = page.getByText("wants to sign in to your account", { exact: false });
  await expect(notice).toContainText(CONNECTOR_NAME);
  await expect(notice).toContainText(new URL(redirectUri).host);
  await expect(notice).toContainText("read write"); // granted scope shown
  await submitForm(page);

  await page.waitForURL(/\/__test\/oidc-callback\?/u, { timeout: 15_000 });
  const cb = new URL(page.url());
  const code = cb.searchParams.get("code");
  expect(code, "the code reached the registered redirect").toBeTruthy();
  expect(cb.searchParams.get("state")).toBe(state);

  // 7. Token exchange — client_id + PKCE verifier + the SAME resource.
  const token = await request.post(`${origin}/auth/token`, {
    form: {
      grant_type: "authorization_code",
      code: code!,
      code_verifier: codeVerifier,
      client_id: clientId,
      resource,
    },
  });
  expect(token.status()).toBe(200);
  const minted = (await token.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    expires_in: number;
  };
  expect(minted.access_token).toBeTruthy();
  expect(minted.refresh_token, "the policy's refresh opt-in pairs a refresh token").toBeTruthy();
  expect(minted.id_token, "NO id_token for dynamic clients (v1)").toBeUndefined();
  // 30-day mcp-session TTL (allow slack for clock skew within the run).
  expect(minted.expires_in).toBeGreaterThan(29 * 24 * 60 * 60);

  // 8. The bearer unlocks the protected resource.
  const mcp = await request.post(`${origin}/mcp`, {
    headers: { authorization: `Bearer ${minted.access_token}` },
  });
  expect(mcp.status()).toBe(200);
  expect((await mcp.json()) as object).toMatchObject({ ok: true });

  // 9. The silent refresh (OAuth 2.1 §4.3) — no browser, no consent: the
  //    rotated pair replaces the old one and keeps /mcp unlocked.
  const refreshed = await request.post(`${origin}/auth/token`, {
    form: {
      grant_type: "refresh_token",
      refresh_token: minted.refresh_token!,
      client_id: clientId,
    },
  });
  expect(refreshed.status()).toBe(200);
  const rotated = (await refreshed.json()) as { access_token: string; refresh_token: string };
  expect(rotated.refresh_token).toBeTruthy();
  expect(rotated.refresh_token, "one-time use: the refresh token ROTATES").not.toBe(
    minted.refresh_token,
  );
  const mcpAfterRefresh = await request.post(`${origin}/mcp`, {
    headers: { authorization: `Bearer ${rotated.access_token}` },
  });
  expect(mcpAfterRefresh.status()).toBe(200);
});

test("AUTHZ-DCR-02: symmetry + resource negatives — missing client_id is 401; mismatched resource is invalid_target", async ({
  page,
  request,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  const connector = await discoverAndRegister(request, origin);
  const { clientId } = connector;

  // A dynamic code redeemed WITHOUT its client_id → 401 invalid_client (the
  // symmetric binding — same rule that already protects Tier 1/2 codes).
  const first = await mintCodeViaBrowser(page, origin, connector);
  const missingClient = await request.post(`${origin}/auth/token`, {
    failOnStatusCode: false,
    form: {
      grant_type: "authorization_code",
      code: first.code,
      code_verifier: first.codeVerifier,
    },
  });
  expect(missingClient.status()).toBe(401);
  expect(((await missingClient.json()) as { error: string }).error).toBe("invalid_client");

  // RFC 8707: the token-leg resource must match the recorded one.
  const second = await mintCodeViaBrowser(page, origin, connector);
  const mismatch = await request.post(`${origin}/auth/token`, {
    failOnStatusCode: false,
    form: {
      grant_type: "authorization_code",
      code: second.code,
      code_verifier: second.codeVerifier,
      client_id: clientId,
      resource: `${origin}/other-resource`,
    },
  });
  expect(mismatch.status()).toBe(400);
  expect(((await mismatch.json()) as { error: string }).error).toBe("invalid_target");
});

test("AUTHZ-DCR-03: confidential connector (client_secret_post, the claude.ai shape) — the secret gates BOTH grants", async ({
  page,
  request,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  const connector = await discoverAndRegister(request, origin, "client_secret_post");
  const { clientId, clientSecret } = connector;
  expect(clientSecret).toBeTruthy();

  const { code, codeVerifier } = await mintCodeViaBrowser(page, origin, connector);

  // The code redeems ONLY with the minted secret.
  const noSecret = await request.post(`${origin}/auth/token`, {
    failOnStatusCode: false,
    form: {
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
      client_id: clientId,
      resource: `${origin}/mcp`,
    },
  });
  expect(noSecret.status()).toBe(401);
  expect(((await noSecret.json()) as { error: string }).error).toBe("invalid_client");

  // The single-use code was consumed by the rejected attempt? NO — client auth
  // failed, but the code WAS consumed atomically before it. Mint a fresh one.
  const retry = await mintCodeViaBrowser(page, origin, connector);
  const token = await request.post(`${origin}/auth/token`, {
    form: {
      grant_type: "authorization_code",
      code: retry.code,
      code_verifier: retry.codeVerifier,
      client_id: clientId,
      client_secret: clientSecret!,
      resource: `${origin}/mcp`,
    },
  });
  expect(token.status()).toBe(200);
  const minted = (await token.json()) as { access_token: string; refresh_token: string };
  expect(minted.refresh_token).toBeTruthy();

  // The refresh grant is secret-gated the same way.
  const refreshNoSecret = await request.post(`${origin}/auth/token`, {
    failOnStatusCode: false,
    form: {
      grant_type: "refresh_token",
      refresh_token: minted.refresh_token,
      client_id: clientId,
    },
  });
  expect(refreshNoSecret.status()).toBe(401);

  const refreshed = await request.post(`${origin}/auth/token`, {
    form: {
      grant_type: "refresh_token",
      refresh_token: minted.refresh_token,
      client_id: clientId,
      client_secret: clientSecret!,
    },
  });
  expect(refreshed.status()).toBe(200);
  const rotated = (await refreshed.json()) as { access_token: string };
  const mcp = await request.post(`${origin}/mcp`, {
    headers: { authorization: `Bearer ${rotated.access_token}` },
  });
  expect(mcp.status()).toBe(200);
});
