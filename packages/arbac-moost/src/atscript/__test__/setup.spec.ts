import { Arbac } from "@aoothjs/arbac-core";
import { createEventContext } from "@wooksjs/event-core";
import { createLogger, Moost } from "moost";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { AutoArbacUserProvider } from "../auto-provider";
import { setupArbacFromAtscript } from "../setup";
import { setUserRecordFetcher } from "../wooks";
import { prepareFixtures } from "./test-utils";

let TestUser: any;
let TestUserOverride: any;

interface UserRow {
  id: string;
  username?: string;
  roles?: string[];
  extraRoles?: string[];
  tenantId?: string;
  department?: string;
}

class InMemoryStore {
  private records = new Map<string, UserRow>();
  put(row: UserRow): void {
    this.records.set(row.id, row);
  }
  read(id: string): Promise<UserRow | null> {
    return Promise.resolve(this.records.get(id) ?? null);
  }
}

class InMemoryTable {
  public lastSelect: Record<string, 1> | undefined;
  private rows: UserRow[];
  constructor(rows: UserRow[]) {
    this.rows = rows;
  }
  async findOne(query: {
    filter: Record<string, unknown>;
    controls?: { $select?: Record<string, 1> };
  }): Promise<UserRow | null> {
    this.lastSelect = query.controls?.$select;
    const row = this.rows.find((r) =>
      Object.entries(query.filter).every(([k, v]) => (r as any)[k] === v),
    );
    return row ?? null;
  }
}

function withLogger<R>(fn: () => R): R {
  const logger = createLogger({ transports: [] });
  return createEventContext({ logger }, fn);
}

describe("setupArbacFromAtscript", () => {
  beforeAll(async () => {
    await prepareFixtures();
    const fixtures = await import("./fixtures/test-user.as");
    TestUser = fixtures.TestUser;
    TestUserOverride = fixtures.TestUserOverride;
  });

  afterEach(() => {
    setUserRecordFetcher(undefined);
  });

  it("requires exactly one of `table` or `store`", () => {
    const moost = new Moost();
    expect(() =>
      setupArbacFromAtscript(moost, {
        userType: TestUser,
        getUserId: () => "u1",
      } as any),
    ).toThrow(/exactly one of `table` or `store`/);

    expect(() =>
      setupArbacFromAtscript(moost, {
        userType: TestUser,
        getUserId: () => "u1",
        table: {} as any,
        store: {} as any,
      }),
    ).toThrow(/exactly one of `table` or `store`/);
  });

  it("throws when the type has no @arbac.userId nor @meta.id field", () => {
    const moost = new Moost();
    const fakeType = { type: { kind: "object", props: new Map() } } as any;
    expect(() =>
      setupArbacFromAtscript(moost, {
        userType: fakeType,
        getUserId: () => "u1",
        store: { read: async () => null },
      }),
    ).toThrow(/no @arbac\.userId or @meta\.id field/);
  });

  it("warns when no @arbac.role fields are declared", () => {
    const moost = new Moost();
    const warnings: string[] = [];
    setupArbacFromAtscript(moost, {
      userType: TestUserOverride,
      getUserId: () => "u1",
      store: { read: async () => null },
      warn: (m) => warnings.push(m),
    });
    // TestUserOverride does have @arbac.role on `role` — so no warning.
    expect(warnings).toEqual([]);

    // Build a synthetic type without role fields.
    const noRoleType = {
      type: {
        kind: "object",
        props: new Map([
          [
            "id",
            {
              __is_atscript_annotated_type: true,
              type: { kind: "", designType: "string", tags: new Set() },
              metadata: new Map([["meta.id", true]]),
            },
          ],
        ]),
      },
    } as any;
    setupArbacFromAtscript(moost, {
      userType: noRoleType,
      getUserId: () => "u1",
      store: { read: async () => null },
      warn: (m) => warnings.push(m),
    });
    expect(warnings.some((m) => /no @arbac\.role fields/.test(m))).toBe(true);
  });

  it("wires a store-backed fetcher and the auto-provider returns the expected roles + attrs", async () => {
    const moost = new Moost();
    const store = new InMemoryStore();
    store.put({
      id: "u1",
      username: "alice",
      roles: ["admin"],
      extraRoles: ["editor"],
      tenantId: "acme",
      department: "eng",
    });

    setupArbacFromAtscript(moost, {
      userType: TestUser,
      getUserId: () => "u1",
      store,
      warn: () => {},
    });

    const provider = new AutoArbacUserProvider(TestUser, () => "u1");
    await withLogger(async () => {
      const id = await provider.getUserId();
      expect(id).toBe("u1");
      const roles = await provider.getRoles(id);
      expect(roles).toEqual(["admin", "editor"]);
      const attrs = await provider.getAttrs(id);
      expect(attrs).toEqual({ tenantId: "acme", department: "eng" });
    });
  });

  it("wires a table-backed fetcher with the projection from getArbacProjection", async () => {
    const moost = new Moost();
    const table = new InMemoryTable([
      {
        id: "u1",
        username: "alice",
        roles: ["admin"],
        extraRoles: [],
        tenantId: "acme",
        department: "eng",
      },
    ]);

    setupArbacFromAtscript(moost, {
      userType: TestUser,
      getUserId: () => "u1",
      table,
      warn: () => {},
    });

    const provider = new AutoArbacUserProvider(TestUser, () => "u1");
    await withLogger(async () => {
      const roles = await provider.getRoles("u1");
      expect(roles).toEqual(["admin"]);
    });

    expect(table.lastSelect).toEqual({
      id: 1,
      roles: 1,
      extraRoles: 1,
      tenantId: 1,
      department: 1,
    });
  });

  it("memoizes the user-record fetch across getRoles + getAttrs within one event", async () => {
    const moost = new Moost();
    let reads = 0;
    const store = {
      read: async (id: string) => {
        reads++;
        return {
          id,
          roles: ["admin"],
          extraRoles: [],
          tenantId: "acme",
          department: "eng",
        };
      },
    };
    setupArbacFromAtscript(moost, {
      userType: TestUser,
      getUserId: () => "u1",
      store,
      warn: () => {},
    });

    const provider = new AutoArbacUserProvider(TestUser, () => "u1");
    await withLogger(async () => {
      await provider.getRoles("u1");
      await provider.getAttrs("u1");
      await provider.getRoles("u1");
    });
    expect(reads).toBe(1);
  });

  it("integrates end-to-end with the real Arbac engine", async () => {
    const moost = new Moost();
    const store = new InMemoryStore();
    store.put({
      id: "u1",
      roles: ["admin"],
      extraRoles: [],
      tenantId: "acme",
      department: "eng",
    });
    setupArbacFromAtscript(moost, {
      userType: TestUser,
      getUserId: () => "u1",
      store,
      warn: () => {},
    });

    const arbac = new Arbac<object, object>();
    arbac.registerRole({
      id: "admin",
      rules: [{ resource: "user", action: "read" }],
    });

    const provider = new AutoArbacUserProvider(TestUser, () => "u1");
    await withLogger(async () => {
      const id = await provider.getUserId();
      const result = await arbac.evaluate(
        { resource: "user", action: "read" },
        {
          id,
          roles: await provider.getRoles(id),
          attrs: () => provider.getAttrs(id),
        },
      );
      expect(result.allowed).toBe(true);
    });
  });

  it("propagates the configured getUserId through the registered Moost provider", async () => {
    const moost = new Moost();
    let externallyResolvedId = "u1";
    setupArbacFromAtscript(moost, {
      userType: TestUser,
      getUserId: () => externallyResolvedId,
      store: { read: async () => null },
      warn: () => {},
    });

    // We don't drive a full Moost event; assert the BoundAutoArbacUserProvider
    // class is registered as a replacement for ArbacUserProvider so the DI
    // container will instantiate it on resolution. Verify by inspecting the
    // private replace registry — Moost stores it on `replace`.
    const replace = (moost as unknown as { replace: Record<symbol, unknown> }).replace;
    expect(replace).toBeDefined();
    const ctorValues = Object.getOwnPropertySymbols(replace).map((s) => replace[s]);
    expect(ctorValues.length).toBeGreaterThan(0);
    const provider = new (ctorValues[0] as new () => AutoArbacUserProvider)();
    expect(await provider.getUserId()).toBe("u1");
    externallyResolvedId = "u2";
    expect(await provider.getUserId()).toBe("u2");
  });
});
