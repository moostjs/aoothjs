// Round-13: dictionaries served by an ARBAC value-help controller. A binding to
// one is kept for a caller who can read it (its `runQuery` grant), and the
// value-help controller's own `/meta` keeps the refs and bindings of a readable
// target. (Own file: moost keeps controller singletons across boots, and a
// controller first built in another boot registers under another app.)
import { allowTableRead, defineRole } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import { clearGlobalWooks, Controller, Inherit, Moost } from "moost";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { request } from "../../__testing__/http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { AsArbacDbController } from "../as-arbac-db-controller";
import { AsArbacJsonValueHelpController } from "../as-arbac-value-help-controller";
import { R13Bound, R13Dict, R13VDict } from "./fixtures/round13-fixtures.as";
import { createSpace } from "./relations-harness";
import type { Harness } from "./relations-harness";

@TableController(R13Dict as never, "r13-dicts")
@ArbacResource("r13dicts")
class DictsC extends AsArbacDbController<typeof R13Dict> {}

@TableController(R13Bound as never, "r13-bound")
@ArbacResource("r13bound")
class BoundC extends AsArbacDbController<typeof R13Bound> {}

@Inherit()
@Controller("r13-vd")
@ArbacResource("r13vd")
class VdC extends AsArbacJsonValueHelpController<typeof R13VDict> {
  constructor(app: Moost) {
    super(R13VDict, [{ id: 1, label: "x" }] as never, app, "r13-vd");
  }
}

let h: Harness;
beforeAll(async () => {
  h = await createSpace([R13Dict, R13Bound]);
});
afterAll(() => h.close());

const props = (body: any) => body.type.type.props;

describe("value-help controllers", () => {
  async function bootVh(grants: string[]) {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, any>();
    let role = defineRole<object, any>().id("r");
    for (const g of grants) role = role.use(allowTableRead(g));
    arbac.registerRole(role.build());
    return bootArbacHttp({
      arbac,
      user: new FakeUserProvider("u1", ["r"]),
      controllers: [DictsC, BoundC, VdC],
      authorize: true,
    });
  }

  it("a binding to a value-help-served dictionary is kept for a caller who can read it", async () => {
    const http = await bootVh(["r13bound", "r13vd"]);
    const r = await request(http, "GET", "/r13-bound/meta");
    expect(props(r.body).toVh.metadata["ui.valueHelp"]).toBeDefined();
  });

  it("…and stripped for a caller without the dictionary's read grant", async () => {
    const http = await bootVh(["r13bound"]);
    const r = await request(http, "GET", "/r13-bound/meta");
    expect(props(r.body).toVh).toBeDefined();
    expect(props(r.body).toVh.metadata["ui.valueHelp"]).toBeUndefined();
  });

  it("the value-help controller's own /meta keeps refs and bindings the caller can read", async () => {
    const http = await bootVh(["r13vd", "r13dicts"]);
    const r = await request(http, "GET", "/r13-vd/meta");
    expect(r.status, r.text).toBe(200);
    expect(props(r.body).bound.metadata["ui.valueHelp"]).toBeDefined();
    expect(props(r.body).chained.ref).toBeDefined();
  });

  it("…and strips them when the target is unreadable", async () => {
    const http = await bootVh(["r13vd"]);
    const r = await request(http, "GET", "/r13-vd/meta");
    expect(props(r.body).bound.metadata["ui.valueHelp"]).toBeUndefined();
    expect(props(r.body).chained.ref).toBeUndefined();
  });
});
