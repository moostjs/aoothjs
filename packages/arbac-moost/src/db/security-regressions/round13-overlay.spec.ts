// Round-13 `/meta` overlay regressions: a `ref` / `ui.valueHelp` binding is
// gated on EVERY node kind (array elements, union members, wildcard props, a
// ref target's own metadata, empty-field refs), bindings to value-help-served
// dictionaries survive for a caller who can read them, an ARBAC value-help
// controller keeps its own readable refs, and a second relation to the same
// table keeps its nested relations.
import { allowTableAction, allowTableRead, defineRole } from "@aooth/arbac";
import { DbAction, DbActionID, InputForm, TableController } from "@atscript/moost-db";
import { Post } from "@moostjs/event-http";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { readerRole, request } from "../../__testing__/http";
import { ArbacResource } from "../../arbac.decorator";
import { AsArbacDbController } from "../as-arbac-db-controller";
import {
  R13Dict,
  R13Form,
  R13Item,
  R13Org,
  R13Task,
  R13User,
} from "./fixtures/round13-fixtures.as";
import { boot, createSpace } from "./relations-harness";
import type { Harness } from "./relations-harness";

@TableController(R13Dict as never, "r13-dicts")
@ArbacResource("r13dicts")
class DictsC extends AsArbacDbController<typeof R13Dict> {}

@TableController(R13Item as never, "r13-items")
@ArbacResource("r13items")
class ItemsC extends AsArbacDbController<typeof R13Item> {
  @Post("actions/tag")
  @DbAction("tag", { label: "tag" })
  tag(@DbActionID() _id: unknown, @InputForm(R13Form as never) _input: unknown) {
    return { ok: true };
  }
}

@TableController(R13Org as never, "r13-orgs")
@ArbacResource("r13orgs")
class OrgsC extends AsArbacDbController<typeof R13Org> {}
@TableController(R13User as never, "r13-users")
@ArbacResource("r13users")
class UsersC extends AsArbacDbController<typeof R13User> {}
@TableController(R13Task as never, "r13-tasks")
@ArbacResource("r13tasks")
class TasksC extends AsArbacDbController<typeof R13Task> {}

let h: Harness;
beforeAll(async () => {
  h = await createSpace([R13Dict, R13Item, R13Org, R13User, R13Task]);
});
afterAll(() => h.close());

const props = (body: any) => body.type.type.props;
const noLeak = (value: unknown) => {
  const json = JSON.stringify(value);
  expect(json).not.toContain("ui.valueHelp");
  expect(json).not.toContain("r13-dicts");
};

describe("every node kind is gated (arrays, unions, aliases, patterns, ref targets)", () => {
  it("an unreadable dictionary leaves no binding or ref on any node of /meta", async () => {
    const { http } = await boot(
      [readerRole("r", { r13items: undefined })],
      [DictsC, ItemsC],
      ["r"],
    );
    const r = await request(http, "GET", "/r13-items/meta");
    expect(r.status, r.text).toBe(200);
    const p = props(r.body);
    for (const name of ["codes", "one", "either", "refs", "arrBound", "bag", "snap"]) {
      expect(p[name], name).toBeDefined();
    }
    noLeak(r.body.type);
  });

  it("a readable dictionary keeps them all (control)", async () => {
    const { http } = await boot(
      [readerRole("r", { r13items: undefined, r13dicts: undefined })],
      [DictsC, ItemsC],
      ["r"],
    );
    const r = await request(http, "GET", "/r13-items/meta");
    const p = props(r.body);
    expect(p.codes.type.of.metadata["ui.valueHelp"]).toBeDefined();
    expect(p.either.type.items[0].metadata["ui.valueHelp"]).toBeDefined();
    expect(p.refs.type.of.ref).toBeDefined();
    expect(p.bag.type.propsPatterns[0].def.metadata["ui.valueHelp"]).toBeDefined();
    expect(p.snap.ref).toBeDefined();
  });

  it("a hidden dictionary field strips the array element binding", async () => {
    const { http } = await boot(
      [readerRole("r", { r13items: undefined, r13dicts: { projection: { code: 0 } } })],
      [DictsC, ItemsC],
      ["r"],
    );
    const r = await request(http, "GET", "/r13-items/meta");
    expect(props(r.body).codes.type.of.metadata["ui.valueHelp"]).toBeUndefined();
    expect(props(r.body).refs.type.of.ref).toBeUndefined();
  });

  it("the form overlay strips wildcard props, array elements and union members", async () => {
    const roles = [
      defineRole<object, any>()
        .id("r")
        .use(allowTableRead("r13items"), allowTableAction("r13items", ["tag"]))
        .build(),
    ];
    const { http } = await boot(roles, [DictsC, ItemsC], ["r"]);
    const r = await request(http, "GET", "/r13-items/meta/form/R13Form");
    expect(r.status, r.text).toBe(200);
    expect(r.body.type.props.note).toBeDefined();
    noLeak(r.body);
  });
});

describe("two relations to the same table", () => {
  it("keeps the nested relation under the second (inlined) use", async () => {
    const { http } = await boot(
      [readerRole("r", { r13tasks: undefined, r13users: undefined, r13orgs: undefined })],
      [OrgsC, UsersC, TasksC],
      ["r"],
    );
    const r = await request(http, "GET", "/r13-tasks/meta");
    const p = props(r.body);
    expect(Object.keys(p.author.type.props)).toContain("org");
    expect(Object.keys(p.editor.type.props)).toContain("org");
  });
});
