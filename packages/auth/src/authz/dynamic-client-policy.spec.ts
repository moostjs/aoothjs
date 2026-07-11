import { describe, expect, it } from "vite-plus/test";

import { AuthorizeError } from "./authz-errors";
import { hashClientSecret, mintClientSecret } from "./client-secret";
import { DynamicClientPolicy } from "./dynamic-client-policy";
import { DynamicClientStoreMemory, type NewDynamicClient } from "./dynamic-client-store";

const BASE: NewDynamicClient = {
  clientName: "Test Connector",
  redirectUris: ["https://connector.example/cb"],
  tokenEndpointAuthMethod: "none",
  grantTypes: ["authorization_code"],
  responseTypes: ["code"],
};

async function setup(rec: Partial<NewDynamicClient> = {}, policyOpts: object = {}) {
  const store = new DynamicClientStoreMemory();
  const client = await store.create({ ...BASE, ...rec });
  const policy = new DynamicClientPolicy({ store, ...policyOpts });
  return { store, client, policy };
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof AuthorizeError) return e.code;
    throw e;
  }
  throw new Error("expected an AuthorizeError");
}

describe("DynamicClientPolicy", () => {
  it("unknown / absent client_id → invalid_client", async () => {
    const { policy } = await setup();
    expect(
      await codeOf(policy.resolveClient({ clientId: "nope", redirectUri: BASE.redirectUris[0] })),
    ).toBe("invalid_client");
    expect(await codeOf(policy.resolveClient({ redirectUri: BASE.redirectUris[0] }))).toBe(
      "invalid_client",
    );
  });

  it("INVARIANT: the resolved client always carries clientId — the symmetric token-endpoint binding depends on it", async () => {
    const { client, policy } = await setup();
    const r = await policy.resolveClient({
      clientId: client.clientId,
      redirectUri: BASE.redirectUris[0],
    });
    expect(r.clientId).toBe(client.clientId);
    expect(r.accessToken).toBe(true);
    expect(r.idToken).toBeUndefined(); // NO id_token for dynamic clients (v1)
    expect(r.clientName).toBe("Test Connector");
  });

  it("https redirect: exact match only — path or host drift is rejected", async () => {
    const { client, policy } = await setup();
    expect(
      await codeOf(
        policy.resolveClient({
          clientId: client.clientId,
          redirectUri: "https://connector.example/cb/extra",
        }),
      ),
    ).toBe("invalid_redirect");
    expect(
      await codeOf(
        policy.resolveClient({
          clientId: client.clientId,
          redirectUri: "https://evil.example/cb",
        }),
      ),
    ).toBe("invalid_redirect");
  });

  it("loopback redirect: the PORT is ignored (RFC 8252 §7.3) but scheme/host/path/query must match", async () => {
    const { client, policy } = await setup({
      redirectUris: ["http://127.0.0.1:33418/cb?x=1"],
    });
    const ok = await policy.resolveClient({
      clientId: client.clientId,
      redirectUri: "http://127.0.0.1:49152/cb?x=1",
    });
    expect(ok.redirectUri).toBe("http://127.0.0.1:49152/cb?x=1");
    for (const uri of [
      "http://localhost:49152/cb?x=1", // host drift (localhost vs 127.0.0.1)
      "http://127.0.0.1:49152/other?x=1", // path drift
      "http://127.0.0.1:49152/cb", // query drift
      "https://connector.example/cb", // non-loopback never gets the relaxation
    ]) {
      expect(
        await codeOf(policy.resolveClient({ clientId: client.clientId, redirectUri: uri })),
      ).toBe("invalid_redirect");
    }
  });

  it("an https entry never becomes port-agnostic", async () => {
    const { client, policy } = await setup({ redirectUris: ["https://connector.example:8443/cb"] });
    expect(
      await codeOf(
        policy.resolveClient({
          clientId: client.clientId,
          redirectUri: "https://connector.example:9443/cb",
        }),
      ),
    ).toBe("invalid_redirect");
  });

  it("granted scope = requested ∩ allowedScopes ∩ registration scope", async () => {
    const { client, policy } = await setup(
      { scope: "read write admin" },
      { allowedScopes: ["read", "write"] },
    );
    const r = await policy.resolveClient({
      clientId: client.clientId,
      redirectUri: BASE.redirectUris[0],
      scope: "read admin other",
    });
    expect(r.scope).toBe("read");
  });

  it("without allowedScopes the grant falls back to requested ∩ registration scope; with neither, requested passes through", async () => {
    const { client, policy } = await setup({ scope: "read" });
    const r = await policy.resolveClient({
      clientId: client.clientId,
      redirectUri: BASE.redirectUris[0],
      scope: "read write",
    });
    expect(r.scope).toBe("read");
    const open = await setup({ scope: undefined });
    const r2 = await open.policy.resolveClient({
      clientId: open.client.clientId,
      redirectUri: BASE.redirectUris[0],
      scope: "anything",
    });
    expect(r2.scope).toBe("anything");
  });

  it("tokenPolicy defaults to dynamic-session/30d, honors the override, and is cloned per resolve", async () => {
    const { client, policy } = await setup();
    const r = await policy.resolveClient({
      clientId: client.clientId,
      redirectUri: BASE.redirectUris[0],
    });
    expect(r.tokenPolicy.kind).toBe("dynamic-session");
    expect(r.tokenPolicy.ttl).toBe(30 * 24 * 60 * 60_000);

    const custom = await setup(
      {},
      {
        tokenPolicy: { kind: "mcp-session", ttl: 1_000, payload: { a: 1 } },
      },
    );
    const r1 = await custom.policy.resolveClient({
      clientId: custom.client.clientId,
      redirectUri: BASE.redirectUris[0],
    });
    const r2 = await custom.policy.resolveClient({
      clientId: custom.client.clientId,
      redirectUri: BASE.redirectUris[0],
    });
    expect(r1.tokenPolicy).toEqual({ kind: "mcp-session", ttl: 1_000, payload: { a: 1 } });
    r1.tokenPolicy.payload!.a = 2;
    expect(r2.tokenPolicy.payload!.a).toBe(1);
  });

  it("resolveClient stamps lastUsedAt (the registration is now exempt from never-used GC)", async () => {
    const { store, client, policy } = await setup();
    await policy.resolveClient({ clientId: client.clientId, redirectUri: BASE.redirectUris[0] });
    expect((await store.get(client.clientId))!.lastUsedAt).toBeDefined();
  });

  it("a touch failure never fails the authorize request", async () => {
    const { store, client, policy } = await setup();
    store.touch = () => Promise.reject(new Error("db down"));
    const r = await policy.resolveClient({
      clientId: client.clientId,
      redirectUri: BASE.redirectUris[0],
    });
    expect(r.clientId).toBe(client.clientId);
  });

  it("authenticateClient: existence is the check (fail closed when GC'd); a spurious secret is ignored", async () => {
    const { store, client, policy } = await setup();
    await expect(
      policy.authenticateClient({ clientId: client.clientId, clientSecret: "spurious" }),
    ).resolves.toBeUndefined();
    await store.delete(client.clientId);
    expect(await codeOf(policy.authenticateClient({ clientId: client.clientId }))).toBe(
      "invalid_client",
    );
  });

  it("authenticateClient: a client_secret_post client must present its minted secret", async () => {
    const secret = mintClientSecret();
    const { client, policy } = await setup({
      tokenEndpointAuthMethod: "client_secret_post",
      clientSecretHash: hashClientSecret(secret),
    });
    await expect(
      policy.authenticateClient({ clientId: client.clientId, clientSecret: secret }),
    ).resolves.toBeUndefined();
    expect(
      await codeOf(policy.authenticateClient({ clientId: client.clientId, clientSecret: "wrong" })),
    ).toBe("invalid_client");
    expect(await codeOf(policy.authenticateClient({ clientId: client.clientId }))).toBe(
      "invalid_client",
    );
  });

  it("hasClient probes the store", async () => {
    const { client, policy } = await setup();
    expect(await policy.hasClient(client.clientId)).toBe(true);
    expect(await policy.hasClient("nope")).toBe(false);
  });
});
