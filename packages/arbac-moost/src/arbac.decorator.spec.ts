import { Get, HttpError, MoostHttp } from "@moostjs/event-http";
import { createEventContext, defineEventKind } from "@wooksjs/event-core";
import {
  clearGlobalWooks,
  Controller,
  createLogger,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  getMoostMate,
  Moost,
  setControllerContext,
} from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import {
  ArbacAction,
  ArbacAuthorize,
  arbacAuthorizeInterceptor,
  ArbacResource,
  ArbacUserProvider,
  ArbacUserProviderToken,
  getArbacMate,
  MoostArbac,
} from "./index";
import { useArbac } from "./arbac.composables";

// ArbacPublic was removed (ISSUE-4); the `arbacPublic` mate flag is now
// written by auth-moost's combined `@Public()`. These tests still need to
// mark a target as arbac-public to exercise the interceptor's `isPublic`
// short-circuit, so they write the mate flag directly to avoid a cross-
// package dep from this lower-tier package.
const ArbacPublic = () => getArbacMate().decorate("arbacPublic", true);

interface DemoScope {
  filter?: Record<string, unknown>;
}

interface DemoAttrs {
  tenantId?: string;
}

class TestUserProvider extends ArbacUserProvider<DemoAttrs> {
  constructor(
    private readonly userId: string,
    private readonly roles: string[],
  ) {
    super();
  }
  override getUserId() {
    return this.userId;
  }
  override getRoles() {
    return this.roles;
  }
  override getAttrs() {
    return {} as DemoAttrs;
  }
}

function buildArbac(): MoostArbac<DemoAttrs, DemoScope> {
  const arbac = new MoostArbac<DemoAttrs, DemoScope>();
  arbac.registerRole({
    id: "admin",
    rules: [
      {
        resource: "demo",
        action: "*",
        scope: () => ({ filter: { tenant: "acme" } }),
      },
    ],
  });
  arbac.registerRole({
    id: "user",
    rules: [
      {
        resource: "demo",
        action: "read",
        scope: () => ({ filter: { tenant: "acme" } }),
      },
    ],
  });
  return arbac;
}

async function bootstrap(opts: { user: TestUserProvider; global?: boolean }): Promise<MoostHttp> {
  @Controller()
  @ArbacResource("demo")
  class DemoController {
    @Get("read")
    @ArbacAction("read")
    @ArbacAuthorize()
    read() {
      const scopes = useArbac().getScopes<DemoScope>();
      return { ok: true, scopes: scopes ?? null };
    }

    @Get("write")
    @ArbacAction("write")
    @ArbacAuthorize()
    write() {
      return { ok: true };
    }

    @Get("public")
    @ArbacPublic()
    pub() {
      return { ok: true, public: true };
    }

    @Get("ungated")
    @ArbacAction("read")
    ungated() {
      return { ok: true, ungated: true };
    }
  }

  const arbac = buildArbac();
  const app = new Moost();
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, TestUserProvider]));
  app.setProvideRegistry(
    createProvideRegistry([TestUserProvider, () => opts.user], [MoostArbac, () => arbac]),
  );
  if (opts.global) {
    app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
  }
  const http = new MoostHttp();
  app.adapter(http);
  app.registerControllers(DemoController);
  await app.init();
  return http;
}

describe("arbacAuthorizeInterceptor (auth-guard primitive)", () => {
  it("carries an empty __authTransports marker for swagger", () => {
    expect(arbacAuthorizeInterceptor.__authTransports).toEqual({});
  });

  it("ArbacAuthorize() decorator writes authTransports metadata for swagger", () => {
    @Controller()
    class Probe {
      @Get("a")
      @ArbacAuthorize()
      a() {
        return null;
      }
    }
    const meta = getMoostMate().read(Probe.prototype, "a") as
      | (Record<string, unknown> & { interceptors?: { handler: unknown }[] })
      | undefined;
    expect(meta?.authTransports).toEqual({});
    const found = meta?.interceptors?.find((i) => i.handler === arbacAuthorizeInterceptor);
    expect(found).toBeDefined();
  });

  it("app.applyGlobalInterceptors registers arbacAuthorizeInterceptor", () => {
    const app = new Moost();
    expect(
      (app as unknown as { interceptors: { handler: unknown }[] }).interceptors.find(
        (i) => i.handler === arbacAuthorizeInterceptor,
      ),
    ).toBeUndefined();
    app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
    const found = (app as unknown as { interceptors: { handler: unknown }[] }).interceptors.find(
      (i) => i.handler === arbacAuthorizeInterceptor,
    );
    expect(found).toBeDefined();
  });
});

describe("arbac authorize HTTP integration", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  it("allows when role permits and exposes scopes via useArbac().getScopes()", async () => {
    const http = await bootstrap({ user: new TestUserProvider("u1", ["admin"]) });
    const res = await http.request("/read");
    expect(res?.status).toBe(200);
    const body = (await res?.json()) as { ok: boolean; scopes: DemoScope[] };
    expect(body.ok).toBe(true);
    expect(body.scopes).toEqual([{ filter: { tenant: "acme" } }]);
  });

  it("denies with 403 when role lacks the action", async () => {
    const http = await bootstrap({ user: new TestUserProvider("u2", ["user"]) });
    const res = await http.request("/write");
    expect(res?.status).toBe(403);
  });

  it("rethrows non-HttpError from evaluate as HttpError(401) preserving original message (ISSUE-3)", async () => {
    class ThrowingUserProvider extends ArbacUserProvider<DemoAttrs> {
      override getUserId(): Promise<string> {
        return Promise.reject(new Error("database unavailable"));
      }
      override getRoles() {
        return [];
      }
      override getAttrs() {
        return {} as DemoAttrs;
      }
    }
    const http = await bootstrap({
      user: new ThrowingUserProvider() as unknown as TestUserProvider,
    });
    const res = await http.request("/read");
    expect(res?.status).toBe(401);
    const body = (await res?.json()) as { message?: string; statusCode?: number };
    expect(body.statusCode).toBe(401);
    expect(body.message).toBe("database unavailable");
  });

  it("bypasses arbac on @ArbacPublic routes", async () => {
    const http = await bootstrap({ user: new TestUserProvider("u3", []) });
    const res = await http.request("/public");
    expect(res?.status).toBe(200);
    const body = (await res?.json()) as { public: boolean };
    expect(body.public).toBe(true);
  });

  it("global guard gates routes WITHOUT @ArbacAuthorize", async () => {
    const http = await bootstrap({
      user: new TestUserProvider("u4", []),
      global: true,
    });
    const res = await http.request("/ungated");
    expect(res?.status).toBe(403);
  });

  it("global guard still honours @ArbacPublic", async () => {
    const http = await bootstrap({
      user: new TestUserProvider("u5", []),
      global: true,
    });
    const res = await http.request("/public");
    expect(res?.status).toBe(200);
  });

  it("a controller method literally named getOne is gated as literal action 'getOne'", async () => {
    @Controller()
    @ArbacResource("demo")
    class GetOneController {
      @Get("item")
      // No @ArbacAction, no @DbAction — method name used as-is.
      getOne() {
        return { ok: true };
      }
    }

    const arbac = new MoostArbac<DemoAttrs, DemoScope>();
    arbac.registerRole({
      id: "viewer",
      rules: [{ resource: "demo", action: "getOne" }],
    });

    const app = new Moost();
    app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, TestUserProvider]));
    app.setProvideRegistry(
      createProvideRegistry(
        [TestUserProvider, () => new TestUserProvider("u6", ["viewer"])],
        [MoostArbac, () => arbac],
      ),
    );
    app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(GetOneController);
    await app.init();

    const res = await http.request("/item");
    expect(res?.status).toBe(200);
  });

  it("interceptor evaluates arbac on non-HTTP event kinds (workflow / CLI)", async () => {
    @Controller()
    @ArbacResource("demo")
    class WfDemoController {
      @ArbacAction("write")
      step() {
        return null;
      }
    }

    const arbac = buildArbac();
    const provide = createProvideRegistry(
      [TestUserProvider, () => new TestUserProvider("u-wf", ["user"])],
      [MoostArbac, () => arbac],
    );
    const replace = createReplaceRegistry([ArbacUserProviderToken, TestUserProvider]);
    const app = new Moost();
    app.setReplaceRegistry(replace);
    app.setProvideRegistry(provide);
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(WfDemoController);
    await app.init();

    const controller = await getMoostInfact().get(WfDemoController, {
      provide,
      replace,
    });
    if (!controller) throw new Error("controller not resolved");

    const logger = createLogger({ transports: [] });
    const fakeWfKind = defineEventKind("WF", {});
    const before = arbacAuthorizeInterceptor.before;
    let threw: unknown;
    let replied = "not-called";
    await createEventContext({ logger }, fakeWfKind, {}, async () => {
      setControllerContext(controller, "step", "");
      try {
        await (before as (reply: (v: unknown) => void) => Promise<void>)((v) => {
          replied = String(v);
        });
      } catch (e) {
        threw = e;
      }
    });
    expect(replied).toBe("not-called");
    expect(threw).toBeInstanceOf(HttpError);
    expect((threw as HttpError).body.statusCode).toBe(403);
  });

  it("interceptor still bypasses non-HTTP events when @ArbacPublic is set", async () => {
    @Controller()
    @ArbacResource("demo")
    @ArbacPublic()
    class PublicWfController {
      @ArbacAction("write")
      step() {
        return null;
      }
    }

    const arbac = buildArbac();
    const provide = createProvideRegistry(
      [TestUserProvider, () => new TestUserProvider("u-wf-pub", [])],
      [MoostArbac, () => arbac],
    );
    const replace = createReplaceRegistry([ArbacUserProviderToken, TestUserProvider]);
    const app = new Moost();
    app.setReplaceRegistry(replace);
    app.setProvideRegistry(provide);
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(PublicWfController);
    await app.init();

    const controller = await getMoostInfact().get(PublicWfController, {
      provide,
      replace,
    });
    if (!controller) throw new Error("controller not resolved");

    const logger = createLogger({ transports: [] });
    const fakeWfKind = defineEventKind("WF", {});
    const before = arbacAuthorizeInterceptor.before;
    let threw: unknown;
    let replied = "not-called";
    await createEventContext({ logger }, fakeWfKind, {}, async () => {
      setControllerContext(controller, "step", "");
      try {
        await (before as (reply: (v: unknown) => void) => Promise<void>)((v) => {
          replied = String(v);
        });
      } catch (e) {
        threw = e;
      }
    });
    expect(threw).toBeUndefined();
    expect(replied).toBe("not-called");
  });
});
