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

import { useArbac } from "./arbac.composables";
import {
  applyArbacGuardGlobally,
  ArbacAction,
  ArbacResource,
  ArbacUserProvider,
  MoostArbac,
} from "./index";

interface DemoScope {
  filter?: Record<string, unknown>;
}

class TestUserProvider extends ArbacUserProvider<Record<string, never>> {
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
    return {} as Record<string, never>;
  }
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

describe("normalizeAutoCrudMethod (via useArbac action chain)", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  it("maps getOne -> one", async () => {
    const http = await bootResolver(GetOneController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("one");
  });

  it("maps getOneComposite -> one", async () => {
    const http = await bootResolver(GetOneCompositeController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("one");
  });

  it("maps removeComposite -> remove", async () => {
    const http = await bootResolver(RemoveCompositeController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("remove");
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

  it("falls back to normalized method when nothing else is set", async () => {
    const http = await bootResolver(GetOneController);
    const res = await http.request("/a");
    expect(await readAction(res)).toBe("one");
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
    const user = new TestUserProvider("u1", ["creator"]);
    app.setReplaceRegistry(createReplaceRegistry([ArbacUserProvider, TestUserProvider]));
    app.setProvideRegistry(
      createProvideRegistry([TestUserProvider, () => user], [MoostArbac, () => arbac]),
    );
    applyArbacGuardGlobally(app);
    const http = new MoostHttp();
    app.adapter(http);
    app.registerControllers(TasksController);
    await app.init();

    const res = await http.request("/tasks/new");
    expect(res?.status).toBe(200);
    expect(await readAction(res)).toBe("new");
  });
});
