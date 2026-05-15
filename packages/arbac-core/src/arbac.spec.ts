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
      scopes: [{}],
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
      scopes: [{}],
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
      scopes: [{}],
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
      scopes: [{}],
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
  it("must pass userId as the second arg to scope functions", async () => {
    const arbac = new Arbac<{ assignment: string[]; userId: string }, { owner: string }>();
    const seen: Array<{ attrs: { assignment: string[]; userId: string }; userId: string }> = [];
    arbac.registerRole({
      id: "com.role.owner",
      rules: [
        {
          action: "read",
          resource: "com.resource.db.docs",
          scope: (attrs, userId) => {
            seen.push({ attrs, userId });
            return { owner: userId };
          },
        },
      ],
    });
    const result = await arbac.evaluate(
      { action: "read", resource: "com.resource.db.docs" },
      {
        id: "alice",
        roles: ["com.role.owner"],
        attrs: { userId: "alice", assignment: ["a", "b"] },
      },
    );
    expect(result).toStrictEqual({ allowed: true, scopes: [{ owner: "alice" }] });
    expect(seen).toEqual([{ attrs: { userId: "alice", assignment: ["a", "b"] }, userId: "alice" }]);
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
      scopes: [{}],
    });
  });

  it("must push universe sentinel for no-scope allow rule (preserves union semantics)", async () => {
    const arbac = new Arbac<
      { tenantId: string; userId: string },
      { filter: { tenantId: string } }
    >();
    arbac.registerRole({
      id: "com.role.super",
      rules: [{ action: "*", resource: "com.resource.**" }],
    });
    arbac.registerRole({
      id: "com.role.viewer",
      rules: [
        {
          action: "read",
          resource: "com.resource.db.tasks",
          scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }),
        },
      ],
    });
    const result = await arbac.evaluate(
      { action: "read", resource: "com.resource.db.tasks" },
      {
        id: "u1",
        roles: ["com.role.super", "com.role.viewer"],
        attrs: { tenantId: "A", userId: "u1" },
      },
    );
    expect(result).toStrictEqual({
      allowed: true,
      scopes: [{}, { filter: { tenantId: "A" } }],
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
        scope: (userAttrs, _userId) => ({ entities: userAttrs.assignment }),
      },
    ],
  });
  return arbac;
}
