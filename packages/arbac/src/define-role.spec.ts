import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "@aoothjs/arbac-core";

import { defineRole } from "./define-role";
import type { TPrivilegeFunction } from "./define-role";

type TestAttrs = { assignment: string[]; userId: string };
type TestScope = { entities: string[] };

describe("defineRole", () => {
  it("must build a role with all fields", () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("admin")
      .name("Administrator")
      .describe("Full access")
      .allow("**", "*")
      .build();

    expect(role).toStrictEqual({
      id: "admin",
      name: "Administrator",
      description: "Full access",
      rules: [{ resource: "**", action: "*" }],
    });
  });

  it("must build a role with only id and rules", () => {
    const role = defineRole().id("minimal").allow("res", "act").build();

    expect(role.id).toBe("minimal");
    expect(role.name).toBeUndefined();
    expect(role.description).toBeUndefined();
    expect(role.rules).toHaveLength(1);
  });

  it("must preserve scope function on allow rules", () => {
    const scopeFn = (attrs: TestAttrs) => ({ entities: attrs.assignment });
    const role = defineRole<TestAttrs, TestScope>()
      .id("scoped")
      .allow("leads", "read", scopeFn)
      .build();

    expect(role.rules[0]).toHaveProperty("scope", scopeFn);
  });

  it("must omit scope property when no scope given", () => {
    const role = defineRole().id("noscope").allow("res", "act").build();

    expect(role.rules[0]).not.toHaveProperty("scope");
  });

  it("must create deny rules with effect: deny", () => {
    const role = defineRole().id("restricted").deny("secrets", "read").build();

    expect(role.rules[0]).toStrictEqual({
      resource: "secrets",
      action: "read",
      effect: "deny",
    });
  });

  it("must compose privilege functions via .use()", () => {
    const priv: TPrivilegeFunction<object, object> = () => [
      { resource: "a", action: "read" },
      { resource: "b", action: "write" },
    ];

    const role = defineRole().id("composed").use(priv).build();

    expect(role.rules).toHaveLength(2);
    expect(role.rules[0]).toStrictEqual({ resource: "a", action: "read" });
    expect(role.rules[1]).toStrictEqual({ resource: "b", action: "write" });
  });

  it("must compose multiple privileges", () => {
    const p1: TPrivilegeFunction<object, object> = () => [{ resource: "a", action: "read" }];
    const p2: TPrivilegeFunction<object, object> = () => [{ resource: "b", action: "write" }];

    const role = defineRole().id("multi").use(p1, p2).build();

    expect(role.rules).toHaveLength(2);
  });

  it("must throw when build is called without id", () => {
    expect(() => defineRole().build()).toThrow("Role id is required");
  });

  it("must allow building an empty role (no rules)", () => {
    const role = defineRole().id("empty").build();
    expect(role.rules).toStrictEqual([]);
  });

  it("must work end-to-end with Arbac", async () => {
    const role = defineRole<TestAttrs, TestScope>()
      .id("employee")
      .allow("leads", "read", (attrs) => ({ entities: attrs.assignment }))
      .deny("leads", "delete")
      .build();

    const arbac = new Arbac<TestAttrs, TestScope>();
    arbac.registerRole(role);

    const user = {
      id: "u1",
      roles: ["employee"],
      attrs: { userId: "u1", assignment: ["111", "222"] },
    };

    expect(await arbac.evaluate({ resource: "leads", action: "read" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{ entities: ["111", "222"] }],
    });

    expect(await arbac.evaluate({ resource: "leads", action: "delete" }, user)).toStrictEqual({
      allowed: false,
    });
  });
});
