import { allowTableRead, defineRole } from "@aooth/arbac";
import { AsJsonValueHelpController } from "@atscript/moost-db";
import { clearGlobalWooks, Controller, Inherit, Moost } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import type { ArbacDbScope } from "../as-arbac-db-controller";
import { ActDoc } from "./fixtures/actions-doc.as";

/**
 * Security regression — a PLAIN (non-ARBAC) value-help controller tagged with
 * `@ArbacResource` applies no ARBAC scope, so the standard table READ grant
 * must not open its data routes: they stay 403 and only `/meta` is served.
 * The scoped contract of `AsArbacJsonValueHelpController` (row filter,
 * projection, hidden-field 400s, fail-closed `prepareRequest`) is pinned in
 * `as-arbac-value-help-controller.spec.ts`.
 */

const ROWS = [
  { id: 1, owner: "u1", status: "open", secret: "s1" },
  { id: 2, owner: "u2", status: "locked", secret: "s2" },
];

@Inherit()
@Controller("vh")
@ArbacResource("vh")
class PlainVhController extends AsJsonValueHelpController<typeof ActDoc> {
  constructor(app: Moost) {
    super(ActDoc, ROWS, app, "vh");
  }
}

describe("plain value-help controller under ARBAC", () => {
  it("a scoped allowTableRead grant does not open the unscoped data routes", async () => {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, ArbacDbScope>();
    arbac.registerRole(
      defineRole<object, ArbacDbScope>()
        .id("table-read")
        .use(
          allowTableRead("vh", {
            scope: () => ({ filter: { owner: "u1" }, projection: { secret: 0 } }),
          }),
        )
        .build(),
    );
    const http = await bootArbacHttp({
      arbac,
      user: new FakeUserProvider("u1", ["table-read"]),
      controllers: [PlainVhController],
      authorize: true,
    });
    const status = async (path: string) => (await http.request(`/vh/${path}`))!.status;
    for (const path of ["query", "pages", "one/2", "one?id=2"]) {
      expect(await status(path), path).toBe(403);
    }
    expect(await status("meta")).toBe(200);
  });
});
