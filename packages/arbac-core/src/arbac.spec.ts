import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "./arbac";

describe("arbac", () => {
  it("must deny when no policies assigned", async () => {
    const arbac = newArbac();
    expect(
      await arbac.evaluate(
        {
          action: "create",
          resource: "com.resource.db.user",
        },
        getUser("noRoles"),
      ),
    ).toStrictEqual({
      allowed: false,
    });
  });
  it("must allow static policy", async () => {
    const arbac = newArbac();
    expect(
      await arbac.evaluate(
        {
          action: "create",
          resource: "com.resource.db.user",
        },
        getUser("user1"),
      ),
    ).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(
      await arbac.evaluate(
        {
          action: "read",
          resource: "com.resource.db.user",
        },
        getUser("user1"),
      ),
    ).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(
      await arbac.evaluate(
        {
          action: "write",
          resource: "com.resource.db.user",
        },
        getUser("user1"),
      ),
    ).toStrictEqual({
      allowed: false,
    });
  });
  it("must allow wild policy", async () => {
    const arbac = newArbac();
    expect(
      await arbac.evaluate(
        {
          action: "write",
          resource: "com.resource.db.any",
        },
        getUser("wildUser"),
      ),
    ).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(
      await arbac.evaluate(
        {
          action: "delete",
          resource: "com.resource.db.any",
        },
        getUser("wildUser"),
      ),
    ).toStrictEqual({
      allowed: true,
      scopes: [],
    });
    expect(
      await arbac.evaluate(
        {
          action: "delete",
          resource: "com.resource.db.findocs",
        },
        getUser("wildUser"),
      ),
    ).toStrictEqual({
      allowed: false,
    });
  });
  it("must return scope based on user attrs", async () => {
    const arbac = newArbac();
    expect(
      await arbac.evaluate(
        {
          action: "read",
          resource: "com.resource.db.leads",
        },
        getUser("employee"),
      ),
    ).toStrictEqual({
      allowed: true,
      scopes: [{ entities: ["1111", "2222"] }],
    });
  });
  it("must respect double asterisk in wildcard", async () => {
    const arbac = newArbac();
    expect(
      await arbac.evaluate(
        {
          action: "whatever-action",
          resource: "com.resource.any.resource.id",
        },
        getUser("superUser"),
      ),
    ).toStrictEqual({
      allowed: true,
      scopes: [],
    });
  });
});

function getUser(id: string) {
  const users: Record<string, string[] | undefined> = {
    noRoles: [],
    user1: ["com.role.static"],
    wildUser: ["com.role.wild"],
    employee: ["com.role.dealer.employee"],
    superUser: ["com.role.super"],
  };
  return {
    id,
    roles: users[id] || [],
    attrs: {
      userId: id,
      assignment: ["1111", "2222"],
    },
  };
}

function newArbac() {
  const arbac = new Arbac<{ assignment: string[]; userId: string }, { entities: string[] }>();
  arbac.registerRole({
    id: "com.role.static",
    rules: [
      {
        action: "create",
        resource: "com.resource.db.user",
      },
      {
        action: "read",
        resource: "com.resource.db.user",
      },
    ],
  });
  arbac.registerRole({
    id: "com.role.wild",
    rules: [
      {
        action: "*",
        resource: "com.resource.db.*",
      },
      {
        action: "delete",
        effect: "deny",
        resource: "com.resource.db.findocs",
      },
    ],
  });
  arbac.registerRole({
    id: "com.role.super",
    rules: [
      {
        action: "*",
        resource: "com.resource.**",
      },
    ],
  });
  arbac.registerRole({
    id: "com.role.dealer.employee",
    rules: [
      {
        action: "read",
        resource: "com.resource.db.leads",
        scope: (userAttrs) => ({ entities: userAttrs.assignment }),
      },
    ],
  });
  return arbac;
}
