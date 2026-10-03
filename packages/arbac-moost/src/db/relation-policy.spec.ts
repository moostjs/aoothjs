import { DbAction } from "@atscript/moost-db";
import { EventContext, run } from "@wooksjs/event-core";
import { Controller, Id } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ArbacAction, ArbacResource } from "../arbac.decorator";
import {
  registerArbacDbTarget,
  relationFilterNameTree,
  requestRelations,
  resolveHandlerArbacIds,
  resolveRequestRelations,
  withNameTree,
} from "./relation-policy";

type Tree = Map<string, Tree>;
const plain = (tree: Tree): unknown => Object.fromEntries([...tree].map(([k, v]) => [k, plain(v)]));

describe("withNameTree", () => {
  it("collects nested and dotted relation names per level", () => {
    const tree = withNameTree([
      { name: "owner", controls: { $with: [{ name: "org" }] } },
      { name: "owner.team" },
      { name: "tags", controls: {} },
      "bare",
      { nope: 1 },
    ]);
    expect(plain(tree)).toEqual({ owner: { org: {}, team: {} }, tags: {}, bare: {} });
  });

  it("stops at the depth cap (deeper relations stay unresolved → hidden)", () => {
    let entry: Record<string, unknown> = { name: "r" };
    for (let i = 0; i < 40; i++) entry = { name: "r", controls: { $with: [entry] } };
    let depth = 0;
    let level = withNameTree([entry]);
    while (level.size > 0) {
      depth++;
      level = level.get("r")!;
    }
    expect(depth).toBe(16);
  });
});

describe("relationFilterNameTree", () => {
  it("collects predicate relations per level, through $and / $or / $not and operands", () => {
    const tree = relationFilterNameTree({
      status: "open",
      ticket: { $some: { team: { $none: { name: "x" } }, status: "open" } },
      $or: [{ labels: { $some: {} } }, { $not: { parent: { $none: {} } } }],
      $and: [{ ticket: { $none: { issues: { $some: {} } } } }],
      title: { $eq: "x" },
    });
    expect(plain(tree)).toEqual({
      ticket: { team: {}, issues: {} },
      labels: {},
      parent: {},
    });
  });

  it("joins $with entries: their sub-filter predicates at the entry's level", () => {
    const tree = relationFilterNameTree(
      { owner: { $some: {} } },
      withNameTree([{ name: "tickets", filter: { issues: { $some: { a: 1 } } } }]),
    );
    expect(plain(tree)).toEqual({ tickets: { issues: {} }, owner: {} });
  });

  it("only reads the filter (a deep-frozen copy is fine)", () => {
    const filter = Object.freeze({ ticket: Object.freeze({ $some: Object.freeze({}) }) });
    expect(plain(relationFilterNameTree(filter))).toEqual({ ticket: {} });
  });
});

describe("resolveHandlerArbacIds — useArbac precedence", () => {
  @Controller()
  @ArbacResource("docs")
  class Docs {
    query() {}

    @Id("legacy")
    @DbAction("archive", { label: "Archive" })
    archive() {}

    @DbAction("flag", { label: "Flag" })
    @ArbacAction("docs.flag")
    flag() {}

    @ArbacResource("audit")
    @Id("audit-read")
    audit() {}
  }

  @Controller()
  class Unnamed {
    query() {}
  }

  const docs = new Docs();
  it.each([
    ["query", "docs", "query"],
    ["archive", "docs", "archive"],
    ["flag", "docs", "docs.flag"],
    ["audit", "audit", "audit-read"],
  ])("%s → %s / %s", (method, resource, action) => {
    expect(resolveHandlerArbacIds(docs, method)).toEqual({ resource, action });
  });

  it("falls back to the class name", () => {
    expect(resolveHandlerArbacIds(new Unnamed(), "query")).toEqual({
      resource: "Unnamed",
      action: "query",
    });
  });
});

describe("registerArbacDbTarget", () => {
  it("ignores controllers without a readable and returns true (field initializer)", () => {
    expect(registerArbacDbTarget({})).toBe(true);
    expect(registerArbacDbTarget({ readable: { type: {} }, app: {} })).toBe(true);
  });
});

describe("requestRelations", () => {
  it("answers only for the readable the request resolved its $with for", async () => {
    const view = { primaryKeys: ["id"], preferredId: ["id"] };
    const source = { primaryKeys: ["id"], preferredId: ["id"] };
    const ctx = new EventContext({ logger: console });
    await run(ctx, async () => {
      await resolveRequestRelations([{}], { $with: [{ name: "owner" }] }, view);
      expect([...(requestRelations(view)?.keys() ?? [])]).toEqual(["owner"]);
      // Another controller evaluated in the same event (a delegation source).
      expect(requestRelations(source)).toBeUndefined();
      expect(requestRelations(undefined)).toBeUndefined();
    });
  });
});
