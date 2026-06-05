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

import { createHash } from "node:crypto";

import { AuthCredential, CredentialStoreMemory, type SessionInfo } from "@aooth/auth";
import { MoostHttp } from "@moostjs/event-http";
import { createHttpApp } from "@wooksjs/event-http";
import { createProvideRegistry, getMoostInfact, Moost } from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import { Wooks } from "wooks";

import { authGuardInterceptor } from "../auth.guard";
import { AuthCodeStoreMemory } from "../authz/auth-code-store";
import { AuthorizeController } from "../authz/authorize.controller";
import {
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "../authz/authz-tokens";
import { LoopbackClientPolicy } from "../authz/client-policy";
import { PendingAuthorizationStoreMemory } from "../authz/pending-authorization-store";

const LOOPBACK = "http://127.0.0.1:5000/callback";
const pkce = (verifier: string): string =>
  createHash("sha256").update(verifier).digest("base64url");

interface Harness {
  request: (
    input: string,
    init?: RequestInit,
  ) => Promise<{ status: number; body: unknown; location: string | null }>;
  auth: AuthCredential;
  pending: PendingAuthorizationStoreMemory;
  codes: AuthCodeStoreMemory;
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

  async function request(input: string, init: RequestInit = {}) {
    const response = await http.request(input, init);
    if (!response) return { status: 0, body: null, location: null };
    const text = await response.text();
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      /* leave as text */
    }
    return { status: response.status, body, location: response.headers.get("location") };
  }

  return { request, auth, pending, codes };
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
});
