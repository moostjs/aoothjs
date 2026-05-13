import { AuthCredential, CredentialStoreMemory } from "@aoothjs/auth";
import { UserService, UserStoreMemory } from "@aoothjs/user";
import { describe, expect, it } from "vite-plus/test";

import { MoostAuthConfig } from "../auth.config";
import { AuthController } from "../auth.controller";
import { authGuardInterceptor } from "../auth.guard";
import { setupAuthMoost } from "../auth.setup";
import { Controller, Moost, TestAdapter, TestHandler } from "./test-utils";

@Controller("smoke")
class SmokeController {
  @TestHandler()
  ping() {
    return "pong";
  }
}

function makeUsers(): UserService {
  return new UserService(new UserStoreMemory());
}

describe("setupAuthMoost", () => {
  it("registers AuthCredential and MoostAuthConfig in the DI container", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);

    const store = new CredentialStoreMemory();
    const auth = new AuthCredential({ store });
    setupAuthMoost(moost, { authCredential: auth, userService: makeUsers() });
    await moost.init();

    const infact = (await import("moost")).getMoostInfact();
    const handler = adapter.handlers[0];
    expect(handler).toBeDefined();
    const instance = await handler.getInstance();

    const resolvedAuth = await infact.getForInstance(instance, AuthCredential);
    expect(resolvedAuth).toBe(auth);

    const config = await infact.getForInstance(instance, MoostAuthConfig);
    expect(config).toBeInstanceOf(MoostAuthConfig);
    expect(config?.cookie.name).toBe("aooth_session");
    expect(config?.cookie.secure).toBe(true);
    expect(config?.cookie.sameSite).toBe("lax");
    expect(config?.enableBearer).toBe(true);
    expect(config?.enableCookie).toBe(true);
  });

  it("registers UserService in the DI container when provided", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);

    const users = makeUsers();
    setupAuthMoost(moost, {
      authCredential: new AuthCredential({ store: new CredentialStoreMemory() }),
      userService: users,
    });
    await moost.init();

    const infact = (await import("moost")).getMoostInfact();
    const instance = await adapter.handlers[0].getInstance();
    const resolved = await infact.getForInstance(instance, UserService);
    expect(resolved).toBe(users);
  });

  it("applies the auth guard interceptor globally", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);
    setupAuthMoost(moost, {
      authCredential: new AuthCredential({ store: new CredentialStoreMemory() }),
      endpoints: false,
    });
    await moost.init();

    const interceptors = (moost as unknown as { interceptors: Array<{ handler: unknown }> })
      .interceptors;
    const globalHandlers = interceptors.map((i) => i.handler);
    expect(globalHandlers).toContain(authGuardInterceptor);
  });

  it("propagates custom cookie name + transport flags into MoostAuthConfig", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);

    const store = new CredentialStoreMemory();
    const auth = new AuthCredential({ store });
    setupAuthMoost(moost, {
      authCredential: auth,
      cookie: { name: "sid", secure: false, sameSite: "strict", domain: "example.com" },
      enableBearer: false,
      enableCookie: true,
      endpoints: false,
    });
    await moost.init();

    const infact = (await import("moost")).getMoostInfact();
    const instance = await adapter.handlers[0].getInstance();
    const config = await infact.getForInstance(instance, MoostAuthConfig);
    expect(config?.cookie.name).toBe("sid");
    expect(config?.cookie.secure).toBe(false);
    expect(config?.cookie.sameSite).toBe("strict");
    expect(config?.cookie.domain).toBe("example.com");
    expect(config?.enableBearer).toBe(false);
    expect(config?.enableCookie).toBe(true);
  });

  it("throws when endpoints are enabled but userService is missing", () => {
    const moost = new Moost();
    moost.adapter(new TestAdapter());
    expect(() =>
      setupAuthMoost(moost, {
        authCredential: new AuthCredential({ store: new CredentialStoreMemory() }),
        // no userService, endpoints defaults to true
      }),
    ).toThrow(/userService.*required/i);
  });

  it("does not require userService when endpoints=false", () => {
    const moost = new Moost();
    moost.adapter(new TestAdapter());
    expect(() =>
      setupAuthMoost(moost, {
        authCredential: new AuthCredential({ store: new CredentialStoreMemory() }),
        endpoints: false,
      }),
    ).not.toThrow();
  });

  it("auto-registers AuthController when endpoints=true", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    setupAuthMoost(moost, {
      authCredential: new AuthCredential({
        store: new CredentialStoreMemory(),
        refresh: { ttl: 60_000 },
      }),
      userService: makeUsers(),
      // endpoints defaults to true
    });
    await moost.init();

    // The AuthController is registered — its `/auth` prefix + handler paths
    // appear in moost's overview.
    const overview = JSON.stringify(moost.getControllersOverview());
    expect(overview).toContain("/auth");
    expect(overview).toContain('"path":"login"');
    expect(overview).toContain('"path":"refresh"');
    expect(overview).toContain('"path":"status"');
  });

  it("does not register AuthController when endpoints=false", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    setupAuthMoost(moost, {
      authCredential: new AuthCredential({ store: new CredentialStoreMemory() }),
      endpoints: false,
    });
    await moost.init();

    const overview = JSON.stringify(moost.getControllersOverview());
    expect(overview).not.toContain("/auth");
    // AuthController class reference still exported for opt-in registration.
    expect(AuthController).toBeDefined();
  });
});
