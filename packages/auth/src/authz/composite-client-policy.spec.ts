import { describe, expect, it } from "vite-plus/test";

import { AuthorizeError } from "./authz-errors";
import { LoopbackClientPolicy } from "./client-policy";
import { CompositeClientPolicy } from "./composite-client-policy";
import { DynamicClientPolicy } from "./dynamic-client-policy";
import { DynamicClientStoreMemory } from "./dynamic-client-store";
import { RegisteredClientPolicy } from "./registered-client-policy";

const composite = new CompositeClientPolicy({
  loopback: new LoopbackClientPolicy(),
  registered: new RegisteredClientPolicy({
    clients: [{ clientId: "svc", redirectUris: ["https://svc.example/cb"] }],
  }),
});

describe("CompositeClientPolicy", () => {
  it("no client_id → loopback policy (accepts a loopback redirect, cli-session)", async () => {
    const r = await composite.resolveClient({ redirectUri: "http://127.0.0.1:8080/cb" });
    expect(r.clientId).toBeUndefined();
    expect(r.tokenPolicy.kind).toBe("cli-session");
  });

  it("no client_id + non-loopback redirect → rejected by the loopback policy", () => {
    expect(() => composite.resolveClient({ redirectUri: "https://svc.example/cb" })).toThrow(
      AuthorizeError,
    );
  });

  it("with client_id → registered policy", async () => {
    const r = await composite.resolveClient({
      clientId: "svc",
      redirectUri: "https://svc.example/cb",
    });
    expect(r.clientId).toBe("svc");
  });

  it("a registered client cannot smuggle a loopback redirect outside its allowlist", () => {
    expect(() =>
      composite.resolveClient({ clientId: "svc", redirectUri: "http://127.0.0.1:8080/cb" }),
    ).toThrow(AuthorizeError);
  });

  it("authenticateClient dispatches: no client_id is a no-op; a bad client_id → registered failure", async () => {
    await expect(Promise.resolve(composite.authenticateClient({}))).resolves.toBeUndefined();
    expect(() => composite.authenticateClient({ clientId: "nope", clientSecret: "x" })).toThrow(
      AuthorizeError,
    );
  });
});

async function setupWithDynamic() {
  const store = new DynamicClientStoreMemory();
  const dynClient = await store.create({
    clientName: "Connector",
    redirectUris: ["https://connector.example/cb"],
    tokenEndpointAuthMethod: "none",
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
  });
  const three = new CompositeClientPolicy({
    loopback: new LoopbackClientPolicy(),
    registered: new RegisteredClientPolicy({
      clients: [{ clientId: "svc", redirectUris: ["https://svc.example/cb"] }],
    }),
    dynamic: new DynamicClientPolicy({ store }),
  });
  return { store, dynClient, three };
}

describe("CompositeClientPolicy — dynamic slot (3-way dispatch by client_id ownership)", () => {
  it("a dynamic client_id routes to the dynamic policy — resolve AND authenticate alike", async () => {
    const { dynClient, three } = await setupWithDynamic();
    const r = await three.resolveClient({
      clientId: dynClient.clientId,
      redirectUri: "https://connector.example/cb",
    });
    expect(r.clientId).toBe(dynClient.clientId);
    expect(r.clientName).toBe("Connector");
    // The redemption-side dispatch must follow ownership too: the static
    // registry doesn't know this id, and routing there would 401 every
    // dynamic redemption.
    await expect(
      Promise.resolve(three.authenticateClient({ clientId: dynClient.clientId })),
    ).resolves.toBeUndefined();
  });

  it("a static client_id routes to the registered policy even when the dynamic store has the same id (static-first, no shadowing)", async () => {
    const { store, three } = await setupWithDynamic();
    // Force an id collision: plant a dynamic row under the static id. Dispatch
    // must STILL pick the static registry — a DCR registration can never
    // pre-empt a statically-registered client.
    const internal = (store as unknown as { store: Map<string, { clientId: string }> }).store;
    const planted = structuredClone([...internal.values()][0]);
    planted.clientId = "svc";
    internal.set("svc", planted as never);
    const r = await three.resolveClient({
      clientId: "svc",
      redirectUri: "https://svc.example/cb",
    });
    expect(r.clientId).toBe("svc");
    expect(r.clientName).toBeUndefined(); // the static "svc" has no clientName — proves the static policy answered
  });

  it("an unknown client_id falls through to the dynamic policy and fails closed there", async () => {
    const { three } = await setupWithDynamic();
    await expect(
      three.resolveClient({ clientId: "ghost", redirectUri: "https://connector.example/cb" }),
    ).rejects.toThrow(AuthorizeError);
    await expect(Promise.resolve(three.authenticateClient({ clientId: "ghost" }))).rejects.toThrow(
      AuthorizeError,
    );
  });

  it("composes {loopback, dynamic} with no static registry", async () => {
    const store = new DynamicClientStoreMemory();
    const client = await store.create({
      redirectUris: ["https://connector.example/cb"],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
    });
    const duo = new CompositeClientPolicy({
      loopback: new LoopbackClientPolicy(),
      dynamic: new DynamicClientPolicy({ store }),
    });
    const r = await duo.resolveClient({
      clientId: client.clientId,
      redirectUri: "https://connector.example/cb",
    });
    expect(r.clientId).toBe(client.clientId);
    const loop = await duo.resolveClient({ redirectUri: "http://127.0.0.1:8080/cb" });
    expect(loop.tokenPolicy.kind).toBe("cli-session");
  });

  it("construction fails loud: no registered/dynamic at all, or both without a hasClient probe", () => {
    expect(() => new CompositeClientPolicy({ loopback: new LoopbackClientPolicy() })).toThrow(
      /at least one/u,
    );
    expect(
      () =>
        new CompositeClientPolicy({
          loopback: new LoopbackClientPolicy(),
          registered: { resolveClient: () => ({}) as never }, // no hasClient
          dynamic: new DynamicClientPolicy({ store: new DynamicClientStoreMemory() }),
        }),
    ).toThrow(/hasClient/u);
  });
});
