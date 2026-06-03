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

import { useArbac } from "./arbac.composables";
import type { AoothArbacClaims } from "./attenuation";
import { ArbacUserProvider, ArbacUserProviderToken, MoostArbac } from "./index";

interface DocScope {
  filter?: Record<string, unknown>;
}
type Attrs = { region: string };

/** Provider that sources attenuation through the optional hook (settable per test). */
class AttnProvider extends ArbacUserProvider<Attrs> {
  public attenuation: AoothArbacClaims | undefined;
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
  override getAttenuation(): AoothArbacClaims | undefined {
    return this.attenuation;
  }
}

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
  return arbac;
}

const ProbeRead = () =>
  Resolve(() => useArbac().evaluate<DocScope>({ resource: "doc", action: "read" }));
const ProbeWrite = () =>
  Resolve(() => useArbac().evaluate<DocScope>({ resource: "doc", action: "write" }));

@Controller("ev")
class EvalController {
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
  path: "read" | "write",
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
    const provider = new AttnProvider("u1", ["regional"], { region: "eu" });
    provider.attenuation = undefined;
    const http = await bootstrap(
      provider,
      AttnProvider as TClassConstructor<ArbacUserProvider<Attrs>>,
    );
    const w = await probe(http, "write");
    expect(w.allowed).toBe(true);
    expect(w.scopes).toStrictEqual([{ filter: { region: "eu" } }]);
  });

  it("roles narrowing → write is denied (allow-AND reached the engine)", async () => {
    const provider = new AttnProvider("u1", ["regional", "reader"], { region: "eu" });
    provider.attenuation = { roles: ["reader"] }; // reader cannot write
    const http = await bootstrap(
      provider,
      AttnProvider as TClassConstructor<ArbacUserProvider<Attrs>>,
    );
    expect((await probe(http, "write")).allowed).toBe(false);
    expect((await probe(http, "read")).allowed).toBe(true);
  });

  it("attrs narrowing → scope is CONJOINED ($and), the credential can't escape the user's region", async () => {
    const provider = new AttnProvider("u1", ["regional"], { region: "eu" });
    provider.attenuation = { attrs: { region: "us" } }; // tries to switch region
    const http = await bootstrap(
      provider,
      AttnProvider as TClassConstructor<ArbacUserProvider<Attrs>>,
    );
    const r = await probe(http, "read");
    expect(r.allowed).toBe(true);
    // $and of the ceiling (eu) and the cred pass (us) → satisfiable only by
    // region ∈ {eu} ∩ {us} = ∅; the token can NEVER see a us row. The merge
    // reached credEval (region became us there) AND was clipped by conjunction.
    expect(r.scopes).toStrictEqual([{ filter: { $and: [{ region: "eu" }, { region: "us" }] } }]);
  });

  it("roles: [] → deny-all", async () => {
    const provider = new AttnProvider("u1", ["regional"], { region: "eu" });
    provider.attenuation = { roles: [] };
    const http = await bootstrap(
      provider,
      AttnProvider as TClassConstructor<ArbacUserProvider<Attrs>>,
    );
    expect((await probe(http, "read")).allowed).toBe(false);
  });

  it("a provider WITHOUT getAttenuation → byte-for-byte unchanged (no $and wrapping)", async () => {
    const provider = new PlainProvider("u1", ["regional"], { region: "eu" });
    const http = await bootstrap(
      provider,
      PlainProvider as TClassConstructor<ArbacUserProvider<Attrs>>,
    );
    const r = await probe(http, "read");
    expect(r.allowed).toBe(true);
    expect(r.scopes).toStrictEqual([{ filter: { region: "eu" } }]);
  });
});
