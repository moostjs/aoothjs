import { describe, expect, it } from "vite-plus/test";

import type { Clock } from "../utils/clock";
import {
  ClientRegistrationError,
  DynamicClientRegistration,
  validateClientRegistration,
} from "./client-registration";
import { DynamicClientStoreMemory } from "./dynamic-client-store";

function fakeClock(start = 1_000_000): Clock & { advance: (ms: number) => void } {
  let now = start;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof ClientRegistrationError) return e.code;
    throw e;
  }
  throw new Error("expected a ClientRegistrationError");
}

const MINIMAL = { redirect_uris: ["https://connector.example/cb"] };

describe("validateClientRegistration", () => {
  it("a minimal https registration normalizes to public-client defaults", () => {
    const rec = validateClientRegistration(MINIMAL);
    expect(rec).toEqual({
      redirectUris: ["https://connector.example/cb"],
      tokenEndpointAuthMethod: "none",
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
    });
  });

  it("rejects a non-object body", () => {
    expect(codeOf(() => validateClientRegistration("nope"))).toBe("invalid_client_metadata");
    expect(codeOf(() => validateClientRegistration(null))).toBe("invalid_client_metadata");
    expect(codeOf(() => validateClientRegistration([MINIMAL]))).toBe("invalid_client_metadata");
  });

  it("redirect_uris is required and must be non-empty", () => {
    expect(codeOf(() => validateClientRegistration({}))).toBe("invalid_redirect_uri");
    expect(codeOf(() => validateClientRegistration({ redirect_uris: [] }))).toBe(
      "invalid_redirect_uri",
    );
  });

  it("rejects custom schemes, plain-http non-loopback hosts, fragments and embedded credentials", () => {
    for (const uri of [
      "myapp://callback", // custom scheme (v1 non-goal)
      "http://connector.example/cb", // http on a real host
      "https://connector.example/cb#frag", // fragment (RFC 6749 §3.1.2)
      "https://user@connector.example/cb", // embedded credentials
      "not a url",
    ]) {
      expect(codeOf(() => validateClientRegistration({ redirect_uris: [uri] }))).toBe(
        "invalid_redirect_uri",
      );
    }
  });

  it("accepts https hosts and loopback literals (the Tier-1 rules), deduping entries", () => {
    const rec = validateClientRegistration({
      redirect_uris: [
        "https://connector.example/cb",
        "http://127.0.0.1:33418/cb",
        "http://[::1]:8000/cb",
        "http://localhost:8000/cb",
        "https://connector.example/cb", // duplicate
      ],
    });
    expect(rec.redirectUris).toHaveLength(4);
  });

  it("caps redirect_uris count and per-URI length (anonymous endpoint, rows stay small)", () => {
    const many = Array.from({ length: 6 }, (_, i) => `https://c.example/cb${i}`);
    expect(codeOf(() => validateClientRegistration({ redirect_uris: many }))).toBe(
      "invalid_redirect_uri",
    );
    const long = `https://c.example/${"x".repeat(600)}`;
    expect(codeOf(() => validateClientRegistration({ redirect_uris: [long] }))).toBe(
      "invalid_redirect_uri",
    );
  });

  it('token_endpoint_auth_method: absent defaults to "none"; an explicit non-"none" ask is rejected, never downgraded', () => {
    expect(validateClientRegistration(MINIMAL).tokenEndpointAuthMethod).toBe("none");
    expect(
      validateClientRegistration({ ...MINIMAL, token_endpoint_auth_method: "none" })
        .tokenEndpointAuthMethod,
    ).toBe("none");
    expect(
      codeOf(() =>
        validateClientRegistration({
          ...MINIMAL,
          token_endpoint_auth_method: "client_secret_basic",
        }),
      ),
    ).toBe("invalid_client_metadata");
  });

  it("grant_types / response_types are INTERSECTED with supported (RFC 7591 §2 narrowing), not rejected", () => {
    const rec = validateClientRegistration({
      ...MINIMAL,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    });
    expect(rec.grantTypes).toEqual(["authorization_code"]);
    expect(rec.responseTypes).toEqual(["code"]);
  });

  it("an empty intersection is rejected (the client cannot use this server at all)", () => {
    expect(
      codeOf(() => validateClientRegistration({ ...MINIMAL, grant_types: ["implicit"] })),
    ).toBe("invalid_client_metadata");
    expect(
      codeOf(() => validateClientRegistration({ ...MINIMAL, response_types: ["token"] })),
    ).toBe("invalid_client_metadata");
  });

  it("client_name is sanitized: bidi overrides / zero-width / control chars stripped, trimmed, capped", () => {
    const rec = validateClientRegistration({
      ...MINIMAL,
      client_name: "  ‮elgoog‬ Sec​urity\r\n ",
    });
    expect(rec.clientName).toBe("elgoog Security");
    const capped = validateClientRegistration({ ...MINIMAL, client_name: "x".repeat(200) });
    expect(capped.clientName).toHaveLength(128);
    // Empty after stripping ⇒ treated as absent.
    expect(validateClientRegistration({ ...MINIMAL, client_name: "‮​" }).clientName).toBeUndefined();
    expect(codeOf(() => validateClientRegistration({ ...MINIMAL, client_name: 42 }))).toBe(
      "invalid_client_metadata",
    );
  });

  it("scope: token charset enforced, allowedScopes intersected, empty result dropped", () => {
    expect(codeOf(() => validateClientRegistration({ ...MINIMAL, scope: 'rea"d' }))).toBe(
      "invalid_client_metadata",
    );
    const rec = validateClientRegistration(
      { ...MINIMAL, scope: "read write admin" },
      { allowedScopes: ["read", "write"] },
    );
    expect(rec.scope).toBe("read write");
    expect(
      validateClientRegistration({ ...MINIMAL, scope: "admin" }, { allowedScopes: ["read"] }).scope,
    ).toBeUndefined();
  });

  it("unknown fields are ignored, never echoed into the record", () => {
    const rec = validateClientRegistration({ ...MINIMAL, software_id: "x", jwks: {} });
    expect(rec).not.toHaveProperty("software_id");
    expect(rec).not.toHaveProperty("jwks");
  });
});

describe("DynamicClientRegistration", () => {
  it("register validates, persists and returns the minted client", async () => {
    const store = new DynamicClientStoreMemory();
    const reg = new DynamicClientRegistration({ store });
    const client = await reg.register({ ...MINIMAL, client_name: "Connector" });
    expect(client.clientId).toBeTruthy();
    expect(client.clientName).toBe("Connector");
    expect(await store.get(client.clientId)).toEqual(client);
  });

  it("guard sees validated metadata and can reject with a 7591 error; other throws propagate as-is", async () => {
    const store = new DynamicClientStoreMemory();
    const rejecting = new DynamicClientRegistration({
      store,
      guard: ({ metadata }) => {
        expect(metadata.redirectUris).toEqual(MINIMAL.redirect_uris);
        throw new ClientRegistrationError("invalid_client_metadata", "not today");
      },
    });
    await expect(rejecting.register(MINIMAL)).rejects.toMatchObject({
      code: "invalid_client_metadata",
      message: "not today",
    });
    const faulty = new DynamicClientRegistration({
      store,
      guard: () => {
        throw new TypeError("boom");
      },
    });
    await expect(faulty.register(MINIMAL)).rejects.toThrow(TypeError);
    expect(await store.count()).toBe(0); // nothing persisted on either failure
  });

  it("maxClients is reject-when-full — used registrations are never evicted", async () => {
    const store = new DynamicClientStoreMemory();
    const reg = new DynamicClientRegistration({ store, maxClients: 1 });
    const first = await reg.register(MINIMAL);
    await expect(reg.register(MINIMAL)).rejects.toMatchObject({
      code: "invalid_client_metadata",
    });
    expect(await store.get(first.clientId)).not.toBeNull();
  });

  it("lazy GC frees never-used capacity on the next register; touched rows survive", async () => {
    const clock = fakeClock();
    const store = new DynamicClientStoreMemory({ clock });
    const reg = new DynamicClientRegistration({
      store,
      maxClients: 2,
      unusedClientTtlMs: 1_000,
      clock,
    });
    const used = await reg.register(MINIMAL);
    const stale = await reg.register(MINIMAL);
    await store.touch(used.clientId, clock.now());
    clock.advance(2_000); // both rows pass the TTL; only `stale` is never-used
    const third = await reg.register(MINIMAL); // GC frees `stale`'s slot
    expect(await store.get(stale.clientId)).toBeNull();
    expect(await store.get(used.clientId)).not.toBeNull();
    expect(await store.get(third.clientId)).not.toBeNull();
  });
});
