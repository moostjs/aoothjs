import { DbAction } from "@atscript/moost-db";
import { Controller, Id } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ArbacAction, ArbacResource } from "../arbac.decorator";
import { registerArbacDbTarget, resolveHandlerArbacIds, withNameTree } from "./relation-policy";

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
