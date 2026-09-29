import { allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import type { TScopeFilter } from "@aooth/arbac";
import { Body, type MoostHttp, Post } from "@moostjs/event-http";
import { clearGlobalWooks, Controller } from "moost";
import { beforeAll, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../arbac.decorator";
import { conjoinArbacDbScopes } from "../attenuation";
import { MoostArbac } from "../moost-arbac";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { registerArbacDbTarget } from "./relation-policy";
import { useArbacDbScope } from "./use-arbac-db-scope";
import { conjoinCheckRefs, enforcedRefs, refForeignKeyOf } from "./write-refs";
import type { RefForeignKey, RefTableSource } from "./write-refs";

const OWNER: RefForeignKey = { fields: ["ownerId"], targetFields: ["id"], targetTable: "users" };
const PROJECT: RefForeignKey = {
  fields: ["projectId"],
  targetFields: ["id"],
  targetTable: "projects",
};
const TABLE: RefTableSource = {
  foreignKeys: new Map([
    ["__auto_ownerId", OWNER],
    ["__auto_projectId", PROJECT],
  ]),
  foreignKeyOf: (rel) => (rel === "project" ? PROJECT : undefined),
};

describe("refForeignKeyOf", () => {
  it("resolves an FK field or the TO relation it backs", () => {
    expect(refForeignKeyOf(TABLE, "ownerId")).toBe(OWNER);
    expect(refForeignKeyOf(TABLE, "project")).toBe(PROJECT);
  });

  it("anything else is a configuration error", () => {
    expect(() => refForeignKeyOf(TABLE, "comments")).toThrow(/not a foreign key field/);
    expect(() => refForeignKeyOf(TABLE, "nope")).toThrow(/checkRefs: "nope"/);
  });
});

describe("enforcedRefs — union rule", () => {
  it("true = every FK; names by field or relation", () => {
    expect(enforcedRefs([{ checkRefs: true }], TABLE)).toEqual([OWNER, PROJECT]);
    expect(enforcedRefs([{ checkRefs: ["project"] }], TABLE)).toEqual([PROJECT]);
  });

  it("enforced only for the FKs EVERY scope enables", () => {
    expect(enforcedRefs([{ checkRefs: ["projectId"] }, { checkRefs: true }], TABLE)).toEqual([
      PROJECT,
    ]);
    expect(enforcedRefs([{ checkRefs: ["project"] }, { checkRefs: ["projectId"] }], TABLE)).toEqual(
      [PROJECT],
    );
    expect(enforcedRefs([{ checkRefs: true }, {}], TABLE)).toEqual([]);
    expect(enforcedRefs([{ checkRefs: ["ownerId"] }, { checkRefs: ["project"] }], TABLE)).toEqual(
      [],
    );
  });

  it("a table without FKs enforces nothing", () => {
    expect(enforcedRefs([{ checkRefs: true }], {})).toEqual([]);
  });
});

describe("conjoinCheckRefs — credential attenuation", () => {
  it("enforces what either side enforces, canonically named", () => {
    expect(conjoinCheckRefs([{ checkRefs: ["project"] }], [{}], TABLE)).toEqual(["projectId"]);
    expect(
      conjoinCheckRefs([{ checkRefs: ["project"] }], [{ checkRefs: ["ownerId"] }], TABLE),
    ).toBe(true);
    expect(conjoinCheckRefs([{}], [{}], TABLE)).toBeUndefined();
  });

  it("without a schema, combines the names as written", () => {
    expect(conjoinCheckRefs([{ checkRefs: true }, { checkRefs: ["a", "b"] }], [{}])).toEqual([
      "a",
      "b",
    ]);
    expect(conjoinCheckRefs([{ checkRefs: ["a"] }, {}], [{ checkRefs: ["b"] }])).toEqual(["b"]);
    expect(conjoinCheckRefs([{}], [{ checkRefs: true }])).toBe(true);
  });

  it("conjoinArbacDbScopes carries it onto the composite scope", () => {
    const [s] = conjoinArbacDbScopes([{ checkRefs: ["project"] }], [{}], { refTable: TABLE });
    expect(s.checkRefs).toEqual(["projectId"]);
    const [none] = conjoinArbacDbScopes([{}], [{}], { refTable: TABLE });
    expect(none).not.toHaveProperty("checkRefs");
  });
});

describe("assertRefsInScope — FK value shapes", () => {
  /** A Mongo-`ObjectId`-like FK value: a class instance, not a plain object. */
  class FakeObjectId {
    constructor(readonly hex: string) {}
  }
  const TargetType = { metadata: new Map([["db.table", "targets"]]) };
  const counted: TScopeFilter[] = [];

  @ArbacResource("targets")
  class TargetController {
    readonly readable = {
      type: TargetType,
      count: async (q: { filter: TScopeFilter }) => {
        counted.push(q.filter);
        const ids = (q.filter.id as { $in: unknown[] }).$in;
        return ids.filter((v) => v instanceof FakeObjectId).length;
      },
    };
  }
  registerArbacDbTarget(new TargetController());

  const CHILD: RefTableSource = {
    foreignKeys: new Map([
      ["fk", { fields: ["refId"], targetFields: ["id"], targetTypeRef: () => TargetType }],
    ]),
  };

  @Controller("child")
  @ArbacResource("child")
  class ChildController {
    @Post("insert")
    @ArbacAction("insert")
    async insert(@Body() row: Record<string, unknown>) {
      const scope = await useArbacDbScope();
      const value = row.refId === "oid" ? new FakeObjectId("1") : row.refId;
      await scope.assertRefsInScope(CHILD, [{ refId: value }]);
      return { ok: true };
    }
  }

  const role = defineRole<object, ArbacDbScope>()
    .id("writer")
    .use(
      allowTableWrite("child", { scope: () => ({ checkRefs: true }) }),
      allowTableRead("targets"),
    )
    .build();

  let http: MoostHttp;
  beforeAll(async () => {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, ArbacDbScope>();
    arbac.registerRole(role);
    http = await bootArbacHttp({
      arbac,
      user: new FakeUserProvider("u1", ["writer"]),
      controllers: [ChildController],
    });
  });

  const post = async (refId: unknown) =>
    (
      await http.request("/child/insert", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refId }),
      })
    )?.status;

  it("accepts a class-instance FK value (e.g. an ObjectId) and counts it on the target", async () => {
    // Regression: any object FK value was treated as an operator shape → 403.
    counted.length = 0;
    expect(await post("oid")).toBe(201);
    expect(counted).toHaveLength(1);
    expect((counted[0].id as { $in: unknown[] }).$in[0]).toBeInstanceOf(FakeObjectId);
  });

  it("rejects plain-object and array FK values (operator shapes) without counting", async () => {
    counted.length = 0;
    expect(await post({ $ne: null })).toBe(403);
    expect(await post(["a"])).toBe(403);
    expect(counted).toHaveLength(0);
  });
});
