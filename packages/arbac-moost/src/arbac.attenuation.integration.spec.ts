import { Get, MoostHttp } from "@moostjs/event-http";
import {
  clearGlobalWooks,
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  Moost,
  Resolve,
  type TClassConstructor,
} from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { FakeUserProvider } from "./__testing__/user-provider";
import { useArbac } from "./arbac.composables";
import { ArbacUserProvider, ArbacUserProviderToken, MoostArbac } from "./index";

interface DocScope {
  filter?: Record<string, unknown>;
  projection?: Record<string, 0 | 1>;
}
type Attrs = { region: string };

/** Provider WITHOUT the hook — the byte-for-byte "no narrowing" path. */
class PlainProvider extends ArbacUserProvider<Attrs> {
  constructor(
    private readonly uid: string,
    public roles: string[],
    private readonly attrs: Attrs,
  ) {
    super();
  }
  override getUserId(): string {
    return this.uid;
  }
  override getRoles(): string[] {
    return this.roles;
  }
  override getAttrs(): Attrs {
    return this.attrs;
  }
}

function buildArbac(): MoostArbac<Attrs, DocScope> {
  const arbac = new MoostArbac<Attrs, DocScope>();
  arbac.registerRole({
    id: "regional",
    rules: [
      { resource: "doc", action: "read", scope: (a) => ({ filter: { region: a.region } }) },
      { resource: "doc", action: "write", scope: (a) => ({ filter: { region: a.region } }) },
    ],
  });
  arbac.registerRole({ id: "reader", rules: [{ resource: "doc", action: "read" }] });
  // `region` doubles as a projection selector for the schema-aware conjunction.
  arbac.registerRole({
    id: "shaped",
    rules: [
      {
        resource: "shape",
        action: "read",
        scope: (a): DocScope => ({ projection: a.region === "narrow" ? { "a.c": 0 } : { a: 1 } }),
      },
    ],
  });
  return arbac;
}

const ProbeRead = () =>
  Resolve(() => useArbac().evaluate<DocScope>({ resource: "doc", action: "read" }));
const ProbeWrite = () =>
  Resolve(() => useArbac().evaluate<DocScope>({ resource: "doc", action: "write" }));

/** A readable other than the (schema-less) current controller's, e.g. a `$with` target. */
const SHAPE_TABLE = {
  primaryKeys: ["id"],
  preferredId: ["id"],
  flatMap: new Map<string, unknown>([
    ["id", {}],
    ["a", {}],
    ["a.b", {}],
    ["a.c", {}],
  ]),
};
const ProbeShape = (table?: typeof SHAPE_TABLE) =>
  Resolve(() => useArbac().evaluate<DocScope>({ resource: "shape", action: "read", table }));

@Controller("ev")
class EvalController {
  @Get("shape")
  shape(@ProbeShape() r?: { allowed: boolean; scopes?: DocScope[] }) {
    return { r };
  }
  @Get("shape-table")
  shapeTable(@ProbeShape(SHAPE_TABLE) r?: { allowed: boolean; scopes?: DocScope[] }) {
    return { r };
  }
  @Get("read")
  read(@ProbeRead() r?: { allowed: boolean; scopes?: DocScope[] }) {
    return { r };
  }
  @Get("write")
  write(@ProbeWrite() r?: { allowed: boolean; scopes?: DocScope[] }) {
    return { r };
  }
}

async function bootstrap(
  provider: ArbacUserProvider<Attrs>,
  providerClass: TClassConstructor<ArbacUserProvider<Attrs>>,
): Promise<MoostHttp> {
  const arbac = buildArbac();
  const app = new Moost();
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, providerClass]));
  app.setProvideRegistry(
    createProvideRegistry([providerClass, () => provider], [MoostArbac, () => arbac]),
  );
  const http = new MoostHttp();
  app.adapter(http);
  app.registerControllers(EvalController);
  await app.init();
  return http;
}

async function probe(
  http: MoostHttp,
  path: "read" | "write" | "shape" | "shape-table",
): Promise<{ allowed: boolean; scopes?: DocScope[] }> {
  const res = await http.request(`/ev/${path}`);
  expect(res?.status).toBe(200);
  const body = (await res!.json()) as { r: { allowed: boolean; scopes?: DocScope[] } };
  return body.r;
}

describe("useArbac().evaluate — credential attenuation wiring", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  it("no attenuation → full user authority (write allowed, scope is the raw single scope)", async () => {
    const provider = new FakeUserProvider<Attrs>("u1", ["regional"], { region: "eu" });
    provider.attenuation = undefined;
    const http = await bootstrap(provider, FakeUserProvider);
    const w = await probe(http, "write");
    expect(w.allowed).toBe(true);
    expect(w.scopes).toStrictEqual([{ filter: { region: "eu" } }]);
  });

  it("roles narrowing → write is denied (allow-AND reached the engine)", async () => {
    const provider = new FakeUserProvider<Attrs>("u1", ["regional", "reader"], { region: "eu" });
    provider.attenuation = { roles: ["reader"] }; // reader cannot write
    const http = await bootstrap(provider, FakeUserProvider);
    expect((await probe(http, "write")).allowed).toBe(false);
    expect((await probe(http, "read")).allowed).toBe(true);
  });

  it("attrs narrowing → scope is CONJOINED ($and), the credential can't escape the user's region", async () => {
    const provider = new FakeUserProvider<Attrs>("u1", ["regional"], { region: "eu" });
    provider.attenuation = { attrs: { region: "us" } }; // tries to switch region
    const http = await bootstrap(provider, FakeUserProvider);
    const r = await probe(http, "read");
    expect(r.allowed).toBe(true);
    // $and of the ceiling (eu) and the cred pass (us) → satisfiable only by
    // region ∈ {eu} ∩ {us} = ∅; the token can NEVER see a us row. The merge
    // reached credEval (region became us there) AND was clipped by conjunction.
    expect(r.scopes).toStrictEqual([{ filter: { $and: [{ region: "eu" }, { region: "us" }] } }]);
  });

  it("roles: [] → deny-all", async () => {
    const provider = new FakeUserProvider<Attrs>("u1", ["regional"], { region: "eu" });
    provider.attenuation = { roles: [] };
    const http = await bootstrap(provider, FakeUserProvider);
    expect((await probe(http, "read")).allowed).toBe(false);
  });

  it("a provider WITHOUT getAttenuation → byte-for-byte unchanged (no $and wrapping)", async () => {
    const provider = new PlainProvider("u1", ["regional"], { region: "eu" });
    const http = await bootstrap(provider, PlainProvider);
    const r = await probe(http, "read");
    expect(r.allowed).toBe(true);
    expect(r.scopes).toStrictEqual([{ filter: { region: "eu" } }]);
  });

  it("evaluate({ table }) conjoins projections against THAT table's schema", async () => {
    const provider = new FakeUserProvider<Attrs>("u1", ["shaped"], { region: "full" });
    provider.attenuation = { attrs: { region: "narrow" } }; // {a:1} ∩ {"a.c":0}
    const http = await bootstrap(provider, FakeUserProvider);
    // With the table's schema the nested exclusion is subtracted exactly.
    const exact = await probe(http, "shape-table");
    expect(exact.allowed).toBe(true);
    expect(exact.scopes).toStrictEqual([{ projection: { "a.b": 1 } }]);
    // Without a schema the parent cannot be split: fail closed (match nothing).
    const closed = await probe(http, "shape");
    expect(closed.scopes?.[0]?.projection).toStrictEqual({ a: 1 });
    expect(closed.scopes?.[0]?.filter).toStrictEqual({ $or: [] });
  });
});
