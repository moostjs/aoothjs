import { describe, expect, it } from "vite-plus/test";

import { AuthorizeError } from "./authz-errors";
import { LoopbackClientPolicy } from "./client-policy";
import { CompositeClientPolicy } from "./composite-client-policy";
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
