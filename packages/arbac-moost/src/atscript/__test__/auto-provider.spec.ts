import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { createEventContext, defineEventKind } from "@wooksjs/event-core";
import { createLogger, createReplaceRegistry, getMoostInfact, Injectable, Moost } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ArbacUserProvider } from "../../user.provider";
import { type ArbacUserTable, AtscriptArbacUserProvider } from "../auto-provider";

// ISSUE-9: AtscriptArbacUserProvider replaces the deleted AutoArbacUserProvider
// plus the loose setupArbacFromAtscript / useUserRecord / extract* helpers.
//
// Building a real `.as` fixture in this test would couple us to the atscript
// compiler. The provider only reads three things off the type — props Map,
// per-prop `metadata.get('arbac.*')`, and `def.kind === 'object'` — so we
// build the minimal annotated-type shape inline. This is the same surface
// `getArbacExtractSpec` consumes; if its contract changes, this fixture
// breaks loudly, which is what we want.

type DemoUser = {
  id: string;
  username: string;
  roles: string[];
  tenantId: string;
};

interface CountingTable extends ArbacUserTable<DemoUser> {
  findOneCalls: number;
}

function makeCountingTable(records: Record<string, DemoUser>): CountingTable {
  const table: CountingTable = {
    findOneCalls: 0,
    async findOne(query) {
      table.findOneCalls += 1;
      const id = query.filter.id as string | undefined;
      if (!id) return null;
      return records[id] ?? null;
    },
  };
  return table;
}

/**
 * Build the minimal `TAtscriptAnnotatedType` shape the provider consumes.
 * Each prop's metadata is a Map keyed by annotation name (e.g. `meta.id`,
 * `arbac.role`, `arbac.attribute`, `arbac.userId`).
 */
function makeAnnotatedType(propAnnotations: Record<string, string[]>): TAtscriptAnnotatedType {
  const props = new Map<string, TAtscriptAnnotatedType>();
  for (const [name, annotations] of Object.entries(propAnnotations)) {
    const metadata = new Map<string, unknown>();
    for (const ann of annotations) metadata.set(ann, true);
    props.set(name, {
      __is_atscript_annotated_type: true,
      type: { kind: "" } as TAtscriptAnnotatedType["type"],
      metadata: metadata as TAtscriptAnnotatedType["metadata"],
      validator: () => ({}) as ReturnType<TAtscriptAnnotatedType["validator"]>,
    });
  }
  return {
    __is_atscript_annotated_type: true,
    type: {
      kind: "object",
      props,
      propsPatterns: [],
      tags: new Set(),
    } as TAtscriptAnnotatedType["type"],
    metadata: new Map() as TAtscriptAnnotatedType["metadata"],
    validator: () => ({}) as ReturnType<TAtscriptAnnotatedType["validator"]>,
  };
}

const DemoUserType = makeAnnotatedType({
  id: ["meta.id"],
  username: [],
  roles: ["arbac.role"],
  tenantId: ["arbac.attribute"],
});

class FixedIdProvider extends AtscriptArbacUserProvider<DemoUser> {
  constructor(
    table: ArbacUserTable<DemoUser>,
    private readonly fixedUserId: string,
    userType: TAtscriptAnnotatedType = DemoUserType,
  ) {
    super(userType, table);
  }
  override getUserId(): string {
    return this.fixedUserId;
  }
  // Expose protected seams so a test can drive them without a fetch hop.
  publicExtractRoles(record: DemoUser): string[] {
    return this.extractRoles(record);
  }
  publicExtractAttrs(record: DemoUser): object {
    return this.extractAttrs(record);
  }
}

const fakeKind = defineEventKind("ARBAC_TEST", {});
const logger = createLogger({ transports: [] });

function inEvent<R>(fn: () => Promise<R> | R): Promise<R> {
  return createEventContext({ logger }, fakeKind, {}, async () => fn());
}

describe("AtscriptArbacUserProvider (ISSUE-9)", () => {
  it("constructor rejects types without @arbac.userId or @meta.id", () => {
    // The constructor guard is the one piece of behavior that fires at boot,
    // not at request time. We protect it explicitly so an unannotated type
    // can't silently produce a provider that always resolves to no record.
    const bogusType = makeAnnotatedType({ name: [] });
    class BadProvider extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(bogusType, {
          async findOne() {
            return null;
          },
        });
      }
      override getUserId() {
        return "ignored";
      }
    }
    expect(() => new BadProvider()).toThrow(/userId|meta\.id/i);
  });

  it("constructor accepts @arbac.userId as an explicit override of @meta.id", () => {
    // Documents the resolution order in getArbacExtractSpec: @arbac.userId
    // wins over @meta.id when both are declared. Consumers rely on this when
    // their JWT subject is e.g. `username`, not the meta id.
    const t = makeAnnotatedType({
      id: ["meta.id"],
      username: ["arbac.userId"],
      roles: ["arbac.role"],
    });
    class P extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(t, {
          async findOne(q) {
            return (
              q.filter.username === "alice"
                ? { id: "u-1", username: "alice", roles: ["admin"], tenantId: "t-1" }
                : null
            ) as DemoUser | null;
          },
        });
      }
      override getUserId() {
        return "alice";
      }
    }
    expect(() => new P()).not.toThrow();
  });

  it("subclass resolves via setReplaceRegistry → DI returns the subclass for ArbacUserProvider", async () => {
    // Encodes the wiring contract documented in app.ts: consumers replace the
    // abstract ArbacUserProvider token with their concrete subclass via
    // setReplaceRegistry, and the DI container hands callers the subclass.
    const table = makeCountingTable({
      "user-1": { id: "user-1", username: "alice", roles: ["admin"], tenantId: "t-1" },
    });
    // ISSUE-9: moost@0.6.x does NOT inherit @Injectable() across `extends`,
    // so every consumer subclass must re-decorate. The same comment lives in
    // app.ts on the real DemoArbacUserProvider — keep them in sync.
    @Injectable()
    class WiredProvider extends FixedIdProvider {
      constructor() {
        super(table, "user-1");
      }
    }
    const replace = createReplaceRegistry([ArbacUserProvider, WiredProvider]);
    const app = new Moost();
    app.setReplaceRegistry(replace);
    await app.init();

    const resolved = await getMoostInfact().get(
      ArbacUserProvider as unknown as new () => ArbacUserProvider,
      { replace },
    );
    expect(resolved).toBeInstanceOf(WiredProvider);
    expect(resolved).toBeInstanceOf(AtscriptArbacUserProvider);
  });

  it("memoizes findOne per event — getRoles + getAttrs share one fetch", async () => {
    // This is THE invariant the wooks-slot WeakMap exists to prove. Two reads
    // in the same event MUST collapse to one DB hit; otherwise every
    // authorize() pass would double-load the user.
    const table = makeCountingTable({
      "user-1": { id: "user-1", username: "alice", roles: ["admin", "editor"], tenantId: "t-1" },
    });
    const provider = new FixedIdProvider(table, "user-1");

    await inEvent(async () => {
      const roles = await provider.getRoles("user-1");
      const attrs = await provider.getAttrs("user-1");
      expect(roles).toEqual(["admin", "editor"]);
      expect(attrs).toEqual({ tenantId: "t-1" });
    });

    expect(table.findOneCalls).toBe(1);
  });

  it("two distinct events do NOT share the cache (per-event isolation)", async () => {
    // The cache lives on the wooks EventContext, not on the provider — so
    // event A's record must not leak into event B. This protects against a
    // future refactor that "optimizes" the cache to a singleton WeakMap.
    const table = makeCountingTable({
      "user-1": { id: "user-1", username: "alice", roles: ["admin"], tenantId: "t-1" },
    });
    const provider = new FixedIdProvider(table, "user-1");

    await inEvent(async () => {
      await provider.getRoles("user-1");
    });
    await inEvent(async () => {
      await provider.getRoles("user-1");
    });

    expect(table.findOneCalls).toBe(2);
  });

  it("extractRoles dedups in first-seen order and drops empty / non-string entries", () => {
    // Encodes the extractRoles contract: array-valued role fields are
    // expanded, falsy / non-string entries are dropped, and duplicates are
    // collapsed in first-seen order. Drives the seam directly so we don't
    // also depend on the fetch path here.
    const table = makeCountingTable({});
    const provider = new FixedIdProvider(table, "ignored");
    const roles = provider.publicExtractRoles({
      id: "u",
      username: "u",
      roles: ["admin", "", "admin", "editor"],
      tenantId: "t-1",
    });
    expect(roles).toEqual(["admin", "editor"]);
  });

  it("getRoles resolves [] when the record is null (deleted user fails closed)", async () => {
    // ARBAC must fail closed on a missing record — the user is treated as
    // having no roles rather than throwing. Throwing would 500 every request
    // from a deleted-but-still-valid-token session, which is a worse UX than
    // 403.
    const table = makeCountingTable({}); // empty store
    const provider = new FixedIdProvider(table, "ghost");
    const roles = await inEvent(() => provider.getRoles("ghost"));
    expect(roles).toEqual([]);
  });

  it("getAttrs returns {} for a type with no @arbac.attribute fields", async () => {
    // Documents the empty-projection behavior. A type that only declares
    // `@arbac.role` must produce `{}` from getAttrs rather than dumping the
    // whole record into the ARBAC eval context.
    const t = makeAnnotatedType({
      id: ["meta.id"],
      roles: ["arbac.role"],
    });
    const table = makeCountingTable({
      "user-1": { id: "user-1", username: "alice", roles: ["admin"], tenantId: "t-1" },
    });
    const provider = new FixedIdProvider(table, "user-1", t);
    const attrs = await inEvent(() => provider.getAttrs("user-1"));
    expect(attrs).toEqual({});
  });
});
