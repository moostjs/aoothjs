import { AuthCredential, CredentialStoreMemory } from "@aoothjs/auth";
import { describe, expect, it } from "vite-plus/test";

import { MoostAuthConfig } from "../auth.config";
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

describe("setupAuthMoost", () => {
  it("registers AuthCredential and MoostAuthConfig in the DI container", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);

    const store = new CredentialStoreMemory();
    const auth = new AuthCredential({ store });
    setupAuthMoost(moost, { authCredential: auth });
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

  it("applies the auth guard interceptor globally", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);
    setupAuthMoost(moost, {
      authCredential: new AuthCredential({ store: new CredentialStoreMemory() }),
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
});
