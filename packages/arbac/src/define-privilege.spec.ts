import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "@aoothjs/arbac-core";

import { canAccess, canCrud, definePrivilege } from "./define-privilege";
import { defineRole } from "./define-role";

type TestAttrs = { department: string };
type TestScope = { dept: string };

describe("definePrivilege", () => {
  it("must create a factory that returns a privilege function", () => {
    const factory = definePrivilege<TestAttrs, TestScope>()((resource: string) => [
      { resource, action: "read" },
    ]);

    const priv = factory("users");
    const rules = priv();
    expect(rules).toStrictEqual([{ resource: "users", action: "read" }]);
  });

  it("must pass through arguments to the factory", () => {
    const factory = definePrivilege<TestAttrs, TestScope>()((resource: string, action: string) => [
      { resource, action },
    ]);

    const rules = factory("articles", "publish")();
    expect(rules).toStrictEqual([{ resource: "articles", action: "publish" }]);
  });

  it("must work with scope in factory", () => {
    const scopeFn = (attrs: TestAttrs) => ({ dept: attrs.department });
    const factory = definePrivilege<TestAttrs, TestScope>()(
      (scope: (attrs: TestAttrs) => TestScope) => [{ resource: "users", action: "read", scope }],
    );

    const rules = factory(scopeFn)();
    expect(rules[0]).toHaveProperty("scope", scopeFn);
  });
});

describe("canAccess", () => {
  it("must return a single allow rule", () => {
    const rules = canAccess("reports", "read")();
    expect(rules).toStrictEqual([{ resource: "reports", action: "read" }]);
  });

  it("must include scope when provided", () => {
    const scopeFn = (attrs: TestAttrs) => ({ dept: attrs.department });
    const rules = canAccess<TestAttrs, TestScope>("reports", "read", scopeFn)();
    expect(rules).toStrictEqual([{ resource: "reports", action: "read", scope: scopeFn }]);
  });

  it("must omit scope when not provided", () => {
    const rules = canAccess("reports", "read")();
    expect(rules[0]).not.toHaveProperty("scope");
  });
});

describe("canCrud", () => {
  it("must generate four CRUD rules", () => {
    const rules = canCrud("articles")();
    expect(rules).toHaveLength(4);
    expect(rules.map((r) => r.action)).toStrictEqual(["create", "read", "update", "delete"]);
    for (const rule of rules) {
      expect(rule.resource).toBe("articles");
    }
  });

  it("must apply scope to all CRUD rules", () => {
    const scopeFn = (attrs: TestAttrs) => ({ dept: attrs.department });
    const rules = canCrud<TestAttrs, TestScope>("articles", scopeFn)();
    for (const rule of rules) {
      expect(rule).toHaveProperty("scope", scopeFn);
    }
  });

  it("must omit scope when not provided", () => {
    const rules = canCrud("articles")();
    for (const rule of rules) {
      expect(rule).not.toHaveProperty("scope");
    }
  });
});

describe("privilege composition in roles", () => {
  it("must compose privileges into a role via .use()", () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("editor")
      .use(canCrud("articles"))
      .use(canAccess("reports", "read"))
      .build();

    expect(role.rules).toHaveLength(5);
  });

  it("must work end-to-end with Arbac", async () => {
    const scopeFn = (attrs: TestAttrs) => ({ dept: attrs.department });

    const role = defineRole<TestAttrs, TestScope>()
      .id("manager")
      .use(canAccess("reports", "read", scopeFn))
      .use(canCrud("articles"))
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = {
      id: "u1",
      roles: ["manager"],
      attrs: { department: "sales" },
    };

    expect(await arbac.evaluate({ resource: "reports", action: "read" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{ dept: "sales" }],
    });

    expect(await arbac.evaluate({ resource: "articles", action: "create" }, user)).toStrictEqual({
      allowed: true,
      scopes: [],
    });

    expect(await arbac.evaluate({ resource: "reports", action: "write" }, user)).toStrictEqual({
      allowed: false,
    });
  });
});
