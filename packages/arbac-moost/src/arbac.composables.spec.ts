import { Get, MoostHttp } from "@moostjs/event-http";
import {
  clearGlobalWooks,
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostMate,
  Moost,
  Resolve,
} from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { FakeUserProvider } from "./__testing__/user-provider";
import { useArbac } from "./arbac.composables";
import {
  ArbacAction,
  arbacAuthorizeInterceptor,
  ArbacResource,
  ArbacUserProviderToken,
  MoostArbac,
} from "./index";

interface DemoScope {
  filter?: Record<string, unknown>;
}

/**
 * Captures the `action` resolved by `useArbac()` for the current handler call.
 * Returned through the response body so each test asserts on a fresh value.
 */
const ResolvedAction = () => Resolve(() => useArbac().action);

/**
 * Decorator that synthesizes the `atscript_db_action` method-meta key without
 * pulling in the @atscript/moost-db runtime — exactly the shape moost-db writes.
 */
function FakeDbAction(name: string) {
  return getMoostMate().decorate("atscript_db_action", { name, opts: {} } as never);
}

/** Decorator that writes moost's generic method `id` slot. */
function MethodId(id: string) {
  return getMoostMate().decorate("id", id);
}

/** Awaits the http response, asserts it exists, and returns the parsed action. */
async function readAction(res: Response | null | undefined): Promise<string> {
  if (!res) throw new Error("response missing");
  const body = (await res.json()) as { action: string };
  return body.action;
}

// Controllers declared at module scope (not inside `it()`) — class declarations
// inside async test functions sometimes lose method-level decorator metadata when
// pre-cached by Mate's read-cache before bind time.
@Controller()
class GetOneController {
  @Get("a")
  getOne(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class GetOneCompositeController {
  @Get("a")
  getOneComposite(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class RemoveCompositeController {
  @Get("a")
  removeComposite(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class MetaFormController {
  @Get("a")
  metaForm(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class FooController {
  @Get("a")
  foo(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class ExplicitWinsController {
  @Get("a")
  @ArbacAction("explicit")
  @FakeDbAction("dbName")
  @MethodId("methodId")
  getOne(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class DbActionWinsController {
  @Get("a")
  @FakeDbAction("dbName")
  @MethodId("methodId")
  getOne(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller()
class IdWinsController {
  @Get("a")
  @MethodId("methodId")
  getOne(@ResolvedAction() action?: string) {
    return { action };
  }
}

@Controller("tasks")
@ArbacResource("tasks")
class TasksController {
  @Get("new")
  @FakeDbAction("new")
  newTask(@ResolvedAction() action?: string) {
    return { action };
  }
}

async function bootResolver(controller: new () => unknown): Promise<MoostHttp> {
  const app = new Moost();
  const http = new MoostHttp();
  app.adapter(http);
  app.registerControllers(controller);
  await app.init();
  return http;
}

describe("useArbac action — literal method name passthrough", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  it("resolves getOne as literal 'getOne'", async () => {
    const http = await bootResolver(GetOneController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("getOne");
  });

  it("resolves getOneComposite as literal 'getOneComposite'", async () => {
    const http = await bootResolver(GetOneCompositeController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("getOneComposite");
  });

  it("resolves removeComposite as literal 'removeComposite'", async () => {
    const http = await bootResolver(RemoveCompositeController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("removeComposite");
  });

  it("resolves metaForm as literal 'metaForm' — NOT normalized to 'meta' (ISSUE-13)", async () => {
    // normalizeAutoCrudMethod was deleted; metaForm must pass through unchanged
    // so that allowTableRead's action list (which contains 'metaForm') matches.
    const http = await bootResolver(MetaFormController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("metaForm");
  });

  it("passes through arbitrary method names like 'foo'", async () => {
    const http = await bootResolver(FooController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("foo");
  });
});

describe("useArbac action-resolution priority", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  it("arbacActionId beats atscript_db_action.name, id, and method", async () => {
    const http = await bootResolver(ExplicitWinsController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("explicit");
  });

  it("atscript_db_action.name beats id and method when no arbacActionId", async () => {
    const http = await bootResolver(DbActionWinsController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("dbName");
  });

  it("id beats normalized method when no arbacActionId / atscript_db_action", async () => {
    const http = await bootResolver(IdWinsController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("methodId");
  });

  it("falls back to literal method name when nothing else is set", async () => {
    const http = await bootResolver(GetOneController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("getOne");
  });
});

describe("useArbac().evaluateOrThrow", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  function buildArbacAllowing(): MoostArbac<Record<string, never>, DemoScope> {
    const arbac = new MoostArbac<Record<string, never>, DemoScope>();
    arbac.registerRole({
      id: "creator",
      rules: [
        {
          resource: "tasks",
          action: "new",
          scope: () => ({ filter: { ok: true } }),
        },
      ],
    });
    return arbac;
  }

  /**
   * Captures the `evaluateOrThrow` outcome (resolved value or thrown HttpError
   * status+message) into the response body so tests can assert on either path.
   */
  const ProbeEvaluateOrThrow = (resource: string, action: string) =>
    Resolve(async () => {
      try {
        const r = await useArbac().evaluateOrThrow({ resource, action });
        return { ok: true as const, allowed: r.allowed, userId: r.userId };
      } catch (err) {
        const e = err as { code?: number; message?: string };
        return { ok: false as const, status: e.code, message: e.message };
      }
    });

  @Controller("probe-allow")
  class ProbeAllowController {
    @Get("a")
    handler(@ProbeEvaluateOrThrow("tasks", "new") result?: unknown) {
      return { result };
    }
  }

  @Controller("probe-deny")
  class ProbeDenyController {
    @Get("a")
    handler(@ProbeEvaluateOrThrow("tasks", "remove") result?: unknown) {
      return { result };
    }
  }

  it("returns { allowed: true, userId } when arbac evaluates allow", async () => {
    const arbac = buildArbacAllowing();
    const app = new Moost();
    const user = new FakeUserProvider("u1", ["creator"]);
    app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, FakeUserProvider]));
    app.setProvideRegistry(
      createProvideRegistry([FakeUserProvider, () => user], [MoostArbac, () => arbac]),
    );
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(ProbeAllowController);
    await app.init();

    const res = await http.request("/probe-allow/a");
    expect(res?.status).toBe(200);
    const body = (await res!.json()) as {
      result: { ok: true; allowed: boolean; userId: string };
    };
    expect(body.result.ok).toBe(true);
    expect(body.result.allowed).toBe(true);
    expect(body.result.userId).toBe("u1");
  });

  it("throws HttpError(403) when arbac evaluates deny", async () => {
    const arbac = buildArbacAllowing();
    const app = new Moost();
    const user = new FakeUserProvider("u1", ["creator"]);
    app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, FakeUserProvider]));
    app.setProvideRegistry(
      createProvideRegistry([FakeUserProvider, () => user], [MoostArbac, () => arbac]),
    );
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(ProbeDenyController);
    await app.init();

    const res = await http.request("/probe-deny/a");
    expect(res?.status).toBe(200);
    const body = (await res!.json()) as {
      result: { ok: false; status: number; message: string };
    };
    expect(body.result.ok).toBe(false);
    expect(body.result.status).toBe(403);
    expect(body.result.message).toContain("tasks");
    expect(body.result.message).toContain("remove");
  });
});

describe("useArbac().evaluate live-read of roles", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  /**
   * The provider instance is registered once with DI; the test rewrites its
   * public `roles` field between requests — never re-registers, never refreshes
   * a token, never touches any persistence layer. Pins the live-read invariant
   * of `useArbac().evaluate()`.
   */

  function buildReaderArbac(): MoostArbac<Record<string, never>, DemoScope> {
    const arbac = new MoostArbac<Record<string, never>, DemoScope>();
    arbac.registerRole({
      id: "reader",
      rules: [{ resource: "thing", action: "read" }],
    });
    return arbac;
  }

  /**
   * Captures `{ allowed }` from a live useArbac().evaluate() call. The
   * resource/action are pinned via opts so the test does not depend on the
   * controller's auto-resolved action name.
   */
  const ProbeEvaluate = () =>
    Resolve(async () => {
      const r = await useArbac().evaluate({ resource: "thing", action: "read" });
      return { allowed: r.allowed };
    });

  @Controller("live")
  class LiveReadController {
    @Get("a")
    handler(@ProbeEvaluate() result?: { allowed: boolean }) {
      return { result };
    }
  }

  /**
   * Pins live-read of roles per evaluate() call. A future optimization that
   * memoizes roles per-request or per-token would silently retain revoked
   * privileges until refresh — this test fails fast on that regression.
   *
   * Read by humans as: "roles must drift with the source of truth, not the
   * token." We mutate the provider's roles field directly between requests —
   * no token refresh, no DB write, no DI re-registration — and assert each
   * subsequent evaluate() reflects the new roles immediately.
   */
  it("re-reads roles from the user provider on every call (no per-token / per-request memoization)", async () => {
    const arbac = buildReaderArbac();
    const provider = new FakeUserProvider("u1", ["reader"]);
    const app = new Moost();
    app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, FakeUserProvider]));
    app.setProvideRegistry(
      createProvideRegistry([FakeUserProvider, () => provider], [MoostArbac, () => arbac]),
    );
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(LiveReadController);
    await app.init();

    const readAllowed = async (): Promise<boolean> => {
      const res = await http.request("/live/a");
      expect(res?.status).toBe(200);
      const body = (await res!.json()) as { result: { allowed: boolean } };
      return body.result.allowed;
    };

    // 1) Initial state: holds "reader" → allowed.
    expect(await readAllowed()).toBe(true);

    // 2) Revoke role in-place. No refresh, no re-register — just a mutation
    //    of the provider's internal state. A cached lookup would still see
    //    ["reader"] and incorrectly allow.
    provider.roles = [];
    expect(await readAllowed()).toBe(false);

    // 3) Restore role in-place. Confirms step (2) wasn't a one-shot bypass —
    //    the next evaluate() truly reads the current value, not a stale one.
    provider.roles = ["reader"];
    expect(await readAllowed()).toBe(true);
  });
});

describe("useArbac integration: @DbAction('new') resolves to action 'new'", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  function buildArbac(): MoostArbac<Record<string, never>, DemoScope> {
    const arbac = new MoostArbac<Record<string, never>, DemoScope>();
    arbac.registerRole({
      id: "creator",
      rules: [
        {
          resource: "tasks",
          action: "new",
          scope: () => ({ filter: { ok: true } }),
        },
      ],
    });
    return arbac;
  }

  it("a method with synthesized @DbAction('new') resolves action 'new' (200 for creator)", async () => {
    const arbac = buildArbac();
    const app = new Moost();
    const user = new FakeUserProvider("u1", ["creator"]);
    app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, FakeUserProvider]));
    app.setProvideRegistry(
      createProvideRegistry([FakeUserProvider, () => user], [MoostArbac, () => arbac]),
    );
    app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(TasksController);
    await app.init();

    const res = await http.request("/tasks/new");
    expect(res?.status).toBe(200);
    expect(await readAction(res)).toBe("new");
  });
});
