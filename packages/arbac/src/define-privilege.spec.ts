import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "@aoothjs/arbac-core";

import { definePrivilege } from "./define-privilege";
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

describe("privilege composition in roles", () => {
  it("must compose privileges into a role via .use()", () => {
    const privRead = definePrivilege<TestAttrs, TestScope>()(() => [
      { resource: "articles", action: "read" },
    ]);
    const privWrite = definePrivilege<TestAttrs, TestScope>()(() => [
      { resource: "articles", action: "write" },
    ]);

    const role = defineRole<TestAttrs, TestScope>()
      .id("editor")
      .use(privRead(), privWrite())
      .build();

    expect(role.rules).toHaveLength(2);
  });

  it("must work end-to-end with Arbac", async () => {
    const scopeFn = (attrs: TestAttrs) => ({ dept: attrs.department });

    const canReadReports = definePrivilege<TestAttrs, TestScope>()(
      (scope: (attrs: TestAttrs) => TestScope) => [{ resource: "reports", action: "read", scope }],
    );

    const role = defineRole<TestAttrs, TestScope>()
      .id("manager")
      .use(canReadReports(scopeFn))
      .allow("articles", "create")
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
      scopes: [{}],
    });

    expect(await arbac.evaluate({ resource: "reports", action: "write" }, user)).toStrictEqual({
      allowed: false,
    });
  });
});
