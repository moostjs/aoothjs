import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "@aoothjs/arbac-core";

import {
  tableActionPrivilege,
  tableActionsPrivilege,
  tableReadPrivilege,
  tableWritePrivilege,
} from "./db-privileges";
import { defineRole } from "./define-role";

type TestAttrs = { tenant: string };
type TestScope = { tenant: string };

const READ_ACTIONS = ["query", "pages", "one", "meta"];
const WRITE_ACTIONS = ["insert", "update", "replace", "remove"];

describe("tableReadPrivilege", () => {
  it("must produce rules for query/pages/one/meta and not for write actions", () => {
    const rules = tableReadPrivilege("tasks")();
    expect(rules.map((r) => r.action)).toStrictEqual(READ_ACTIONS);
    for (const rule of rules) {
      expect(rule.resource).toBe("tasks");
      expect(rule).not.toHaveProperty("scope");
    }
  });

  it("must attach the scope function to every rule when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = tableReadPrivilege<TestAttrs, TestScope>("tasks", { scope })();
    expect(rules).toHaveLength(READ_ACTIONS.length);
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scope);
    }
  });
});

describe("tableWritePrivilege", () => {
  it("must cover all 8 actions (read 4 + write 4)", () => {
    const rules = tableWritePrivilege("tasks")();
    expect(rules).toHaveLength(8);
    expect(rules.map((r) => r.action)).toStrictEqual([...READ_ACTIONS, ...WRITE_ACTIONS]);
    for (const rule of rules) {
      expect(rule.resource).toBe("tasks");
      expect(rule).not.toHaveProperty("scope");
    }
  });

  it("must attach the scope function to every rule when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = tableWritePrivilege<TestAttrs, TestScope>("tasks", { scope })();
    expect(rules).toHaveLength(8);
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scope);
    }
  });
});

describe("tableActionPrivilege", () => {
  it("must produce exactly one rule for the named action", () => {
    const rules = tableActionPrivilege("tasks", "markDone")();
    expect(rules).toStrictEqual([{ resource: "tasks", action: "markDone" }]);
  });

  it("must attach the scope function when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = tableActionPrivilege<TestAttrs, TestScope>("tasks", "markDone", { scope })();
    expect(rules).toStrictEqual([{ resource: "tasks", action: "markDone", scope }]);
  });
});

describe("tableActionsPrivilege", () => {
  it("must produce one rule per supplied action", () => {
    const rules = tableActionsPrivilege("tasks", ["markDone", "archive", "duplicate"])();
    expect(rules.map((r) => r.action)).toStrictEqual(["markDone", "archive", "duplicate"]);
    for (const rule of rules) {
      expect(rule.resource).toBe("tasks");
    }
  });

  it("must attach the scope function to every rule when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = tableActionsPrivilege<TestAttrs, TestScope>("tasks", ["markDone", "archive"], {
      scope,
    })();
    expect(rules).toHaveLength(2);
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scope);
    }
  });

  it("must produce zero rules for an empty action list", () => {
    const rules = tableActionsPrivilege("tasks", [])();
    expect(rules).toStrictEqual([]);
  });
});

describe("composition with defineRole + end-to-end with Arbac", () => {
  it("must compose with defineRole().use(...) and gate read actions correctly", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("tasks-reader")
      .use(tableReadPrivilege("tasks"))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = { id: "u1", roles: ["tasks-reader"], attrs: { tenant: "acme" } };

    expect(await arbac.evaluate({ resource: "tasks", action: "query" }, user)).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "pages" }, user)).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "one" }, user)).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "insert" }, user)).toStrictEqual({
      allowed: false,
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "remove" }, user)).toStrictEqual({
      allowed: false,
    });
  });

  it("must propagate scope from tableWritePrivilege through Arbac.evaluate", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("tasks-writer")
      .use(tableWritePrivilege("tasks", { scope: (attrs) => ({ tenant: attrs.tenant }) }))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = { id: "u1", roles: ["tasks-writer"], attrs: { tenant: "acme" } };

    expect(await arbac.evaluate({ resource: "tasks", action: "update" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{ tenant: "acme" }],
    });
  });

  it("must compose tableActionPrivilege via .use() and gate exactly that action", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("task-mark-done")
      .use(tableActionPrivilege("tasks", "markDone"))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = { id: "u1", roles: ["task-mark-done"], attrs: { tenant: "acme" } };

    expect(await arbac.evaluate({ resource: "tasks", action: "markDone" }, user)).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "archive" }, user)).toStrictEqual({
      allowed: false,
    });
  });
});
