import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "@aooth/arbac-core";

import { allowTableAction, allowTableRead, allowTableWrite } from "./db-privileges";
import * as dbPrivilegesModule from "./db-privileges";
import { defineRole } from "./define-role";

type TestAttrs = { tenant: string };
type TestScope = { tenant: string };

const READ_ACTIONS = ["query", "pages", "getOne", "getOneComposite", "meta", "metaForm"];
const WRITE_ACTIONS = ["insert", "update", "replace", "remove", "removeComposite"];

describe("allowTableRead", () => {
  it("must produce rules for all read actions and not for write actions", () => {
    const rules = allowTableRead("tasks")();
    expect(rules.map((r) => r.action)).toStrictEqual(READ_ACTIONS);
    for (const rule of rules) {
      expect(rule.resource).toBe("tasks");
      expect(rule).not.toHaveProperty("scope");
    }
  });

  it("must attach the scope function to every rule when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = allowTableRead<TestAttrs, TestScope>("tasks", { scope })();
    expect(rules).toHaveLength(READ_ACTIONS.length);
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scope);
    }
  });
});

describe("allowTableWrite", () => {
  it("must cover all read + write actions", () => {
    const rules = allowTableWrite("tasks")();
    expect(rules).toHaveLength(READ_ACTIONS.length + WRITE_ACTIONS.length);
    expect(rules.map((r) => r.action)).toStrictEqual([...READ_ACTIONS, ...WRITE_ACTIONS]);
    for (const rule of rules) {
      expect(rule.resource).toBe("tasks");
      expect(rule).not.toHaveProperty("scope");
    }
  });

  it("must attach the scope function to every rule when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = allowTableWrite<TestAttrs, TestScope>("tasks", { scope })();
    expect(rules).toHaveLength(READ_ACTIONS.length + WRITE_ACTIONS.length);
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scope);
    }
  });
});

describe("allowTableAction — single name (string)", () => {
  it("must produce exactly one rule for the named action", () => {
    const rules = allowTableAction("tasks", "markDone")();
    expect(rules).toStrictEqual([{ resource: "tasks", action: "markDone" }]);
  });

  it("must attach the scope function when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = allowTableAction<TestAttrs, TestScope>("tasks", "markDone", { scope })();
    expect(rules).toStrictEqual([{ resource: "tasks", action: "markDone", scope }]);
  });
});

describe("allowTableAction — multiple names (array)", () => {
  it("must produce one rule per supplied action", () => {
    const rules = allowTableAction("tasks", ["markDone", "archive", "duplicate"])();
    expect(rules.map((r) => r.action)).toStrictEqual(["markDone", "archive", "duplicate"]);
    for (const rule of rules) {
      expect(rule.resource).toBe("tasks");
    }
  });

  it("must attach the scope function to every rule when opts.scope is given", () => {
    const scope = (attrs: TestAttrs) => ({ tenant: attrs.tenant });
    const rules = allowTableAction<TestAttrs, TestScope>("tasks", ["markDone", "archive"], {
      scope,
    })();
    expect(rules).toHaveLength(2);
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scope);
    }
  });

  it("must produce zero rules for an empty action list", () => {
    const rules = allowTableAction("tasks", [])();
    expect(rules).toStrictEqual([]);
  });
});

describe("allowTableAction — string/array parity (ISSUE-21)", () => {
  // Design contract: allowTableAction(r, "x") must produce identical rules to
  // allowTableAction(r, ["x"]). The merged signature must not silently diverge
  // based on whether the caller passes a string vs a single-element array.
  it("allowTableAction(r, 'insert') and allowTableAction(r, ['insert']) produce identical rules", () => {
    const fromString = allowTableAction("tasks", "insert")();
    const fromArray = allowTableAction("tasks", ["insert"])();
    expect(fromString).toStrictEqual(fromArray);
  });
});

describe("db-privileges module — removed names absent (ISSUE-21)", () => {
  // Hard-cut contract: the old privilege factories were renamed.
  // These tests make any re-introduction of the old names a test failure,
  // preventing silent breakage of downstream callers who expect the new API.
  it("tableReadPrivilege is NOT exported from db-privileges", () => {
    expect("tableReadPrivilege" in dbPrivilegesModule).toBe(false);
  });
  it("tableWritePrivilege is NOT exported from db-privileges", () => {
    expect("tableWritePrivilege" in dbPrivilegesModule).toBe(false);
  });
  it("tableActionsPrivilege is NOT exported from db-privileges", () => {
    expect("tableActionsPrivilege" in dbPrivilegesModule).toBe(false);
  });
  it("tableActionPrivilege is NOT exported from db-privileges", () => {
    expect("tableActionPrivilege" in dbPrivilegesModule).toBe(false);
  });
});

describe("composition with defineRole + end-to-end with Arbac", () => {
  it("must compose with defineRole().use(...) and gate read actions correctly", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("tasks-reader")
      .use(allowTableRead("tasks"))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = { id: "u1", roles: ["tasks-reader"], attrs: { tenant: "acme" } };

    expect(await arbac.evaluate({ resource: "tasks", action: "query" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{}],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "pages" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{}],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "getOne" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{}],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "insert" }, user)).toStrictEqual({
      allowed: false,
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "remove" }, user)).toStrictEqual({
      allowed: false,
    });
  });

  it("must propagate scope from allowTableWrite through Arbac.evaluate", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("tasks-writer")
      .use(allowTableWrite("tasks", { scope: (attrs) => ({ tenant: attrs.tenant }) }))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = { id: "u1", roles: ["tasks-writer"], attrs: { tenant: "acme" } };

    expect(await arbac.evaluate({ resource: "tasks", action: "update" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{ tenant: "acme" }],
    });
  });

  it("must compose allowTableAction via .use() and gate exactly that action", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("task-mark-done")
      .use(allowTableAction("tasks", "markDone"))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = { id: "u1", roles: ["task-mark-done"], attrs: { tenant: "acme" } };

    expect(await arbac.evaluate({ resource: "tasks", action: "markDone" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{}],
    });
    expect(await arbac.evaluate({ resource: "tasks", action: "archive" }, user)).toStrictEqual({
      allowed: false,
    });
  });
});
