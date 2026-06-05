import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vite-plus/test";
import { authorize, AuthorizeError } from "./index";

// ── A tiny real HTTP server standing in for the authorization server's
//    /token (+ optional /status) endpoints. No mocking of global fetch. ──
interface Fake {
  tokenUrl: string;
  statusUrl: string;
  lastTokenBody: () => URLSearchParams | undefined;
}

const servers: Server[] = [];

function fakeServer(handlers: {
  token: (body: URLSearchParams) => { status: number; json: unknown };
  status?: (authz: string | undefined) => { status: number; json: unknown };
}): Promise<Fake> {
  let lastBody: URLSearchParams | undefined;
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/token") {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        lastBody = new URLSearchParams(Buffer.concat(chunks).toString());
        const { status, json } = handlers.token(lastBody);
        res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(json));
      });
      return;
    }
    if (url.pathname === "/status" && handlers.status) {
      const { status, json } = handlers.status(req.headers.authorization);
      res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(json));
      return;
    }
    res.writeHead(404).end();
  });
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        tokenUrl: `http://127.0.0.1:${port}/token`,
        statusUrl: `http://127.0.0.1:${port}/status`,
        lastTokenBody: () => lastBody,
      });
    });
  });
}

/** Stand in for the browser: hit the loopback redirect_uri the helper printed. */
function simulateBrowser(
  authUrl: string,
  override?: { state?: string; code?: string; error?: string },
): void {
  const u = new URL(authUrl);
  const cb = new URL(u.searchParams.get("redirect_uri") ?? "");
  if (override?.error) {
    cb.searchParams.set("error", override.error);
  } else {
    cb.searchParams.set("code", override?.code ?? "test-code");
    cb.searchParams.set("state", override?.state ?? u.searchParams.get("state") ?? "");
  }
  void fetch(cb.toString()).catch(() => {});
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

describe("authorize (loopback login)", () => {
  it("completes the round trip and returns the token", async () => {
    const fake = await fakeServer({
      token: () => ({
        status: 200,
        json: { access_token: "tok-1", token_type: "Bearer", expires_in: 2592000, userId: "u-1" },
      }),
    });

    const result = await authorize({
      authorizeUrl: "https://main.example.com/auth/authorize",
      tokenUrl: fake.tokenUrl,
      openBrowser: false,
      onUrl: (url) => simulateBrowser(url),
    });

    expect(result).toEqual({ accessToken: "tok-1", expiresIn: 2592000, userId: "u-1" });
  });

  it("builds an S256 PKCE request whose verifier matches the challenge", async () => {
    let challenge = "";
    const fake = await fakeServer({
      token: () => ({ status: 200, json: { access_token: "tok" } }),
    });

    await authorize({
      authorizeUrl: "https://main.example.com/auth/authorize",
      tokenUrl: fake.tokenUrl,
      clientId: "cli",
      scope: ["api", "profile"],
      openBrowser: false,
      onUrl: (url) => {
        const u = new URL(url);
        expect(u.searchParams.get("response_type")).toBe("code");
        expect(u.searchParams.get("code_challenge_method")).toBe("S256");
        expect(u.searchParams.get("client_id")).toBe("cli");
        expect(u.searchParams.get("scope")).toBe("api profile");
        challenge = u.searchParams.get("code_challenge") ?? "";
        simulateBrowser(url);
      },
    });

    const verifier = fake.lastTokenBody()?.get("code_verifier") ?? "";
    expect(verifier).not.toBe("");
    const recomputed = createHash("sha256").update(verifier).digest().toString("base64url");
    expect(recomputed).toBe(challenge);
    expect(fake.lastTokenBody()?.get("grant_type")).toBe("authorization_code");
    expect(fake.lastTokenBody()?.get("client_id")).toBe("cli");
  });

  it("rejects a callback whose state does not match (CSRF)", async () => {
    const fake = await fakeServer({ token: () => ({ status: 200, json: { access_token: "x" } }) });
    await expect(
      authorize({
        authorizeUrl: "https://main.example.com/auth/authorize",
        tokenUrl: fake.tokenUrl,
        openBrowser: false,
        onUrl: (url) => simulateBrowser(url, { state: "attacker-state" }),
      }),
    ).rejects.toMatchObject({ code: "state_mismatch" });
  });

  it("rejects when the provider returns ?error= (user declined)", async () => {
    const fake = await fakeServer({ token: () => ({ status: 200, json: { access_token: "x" } }) });
    await expect(
      authorize({
        authorizeUrl: "https://main.example.com/auth/authorize",
        tokenUrl: fake.tokenUrl,
        openBrowser: false,
        onUrl: (url) => simulateBrowser(url, { error: "access_denied" }),
      }),
    ).rejects.toMatchObject({ code: "provider_denied" });
  });

  it("maps a non-2xx token response to exchange_failed", async () => {
    const fake = await fakeServer({
      token: () => ({ status: 400, json: { error: "invalid_grant" } }),
    });
    await expect(
      authorize({
        authorizeUrl: "https://main.example.com/auth/authorize",
        tokenUrl: fake.tokenUrl,
        openBrowser: false,
        onUrl: (url) => simulateBrowser(url),
      }),
    ).rejects.toMatchObject({ code: "exchange_failed" });
  });

  it("adopts userId from the statusUrl confirmation when the token lacks one", async () => {
    const fake = await fakeServer({
      token: () => ({ status: 200, json: { access_token: "tok-2", expires_in: 60 } }),
      status: (authz) => ({
        status: authz === "Bearer tok-2" ? 200 : 401,
        json: { userId: "u-from-status" },
      }),
    });

    const result = await authorize({
      authorizeUrl: "https://main.example.com/auth/authorize",
      tokenUrl: fake.tokenUrl,
      statusUrl: fake.statusUrl,
      openBrowser: false,
      onUrl: (url) => simulateBrowser(url),
    });

    expect(result.userId).toBe("u-from-status");
  });

  it("times out when no callback arrives", async () => {
    const fake = await fakeServer({ token: () => ({ status: 200, json: { access_token: "x" } }) });
    await expect(
      authorize({
        authorizeUrl: "https://main.example.com/auth/authorize",
        tokenUrl: fake.tokenUrl,
        openBrowser: false,
        timeoutMs: 80,
        onUrl: () => {
          /* never simulate the browser → the listener should time out */
        },
      }),
    ).rejects.toMatchObject({ code: "timeout" });
  });

  it("exposes AuthorizeError as the thrown type", async () => {
    const fake = await fakeServer({ token: () => ({ status: 200, json: { access_token: "x" } }) });
    const err = await authorize({
      authorizeUrl: "https://main.example.com/auth/authorize",
      tokenUrl: fake.tokenUrl,
      openBrowser: false,
      onUrl: (url) => simulateBrowser(url, { error: "denied" }),
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthorizeError);
  });
});
