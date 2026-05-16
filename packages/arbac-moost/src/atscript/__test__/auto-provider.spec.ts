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

// ISSUE-18: refinements to `@arbac.*` annotation interpretation.
//
// The post-ISSUE-9 `resolveIdentifierField` chain (read in auto-provider.ts) is:
//   1. explicit `@arbac.userId` field
//   2. field captured by `@db.table.preferredId.uniqueIndex` (type-level
//      metadata; value is the unique-index group name OR `true` to pick the
//      first single-field group)
//   3. `@meta.id`
//
// Multi-`@arbac.role` is now fail-loud at spec time. `@arbac.role` can be
// declared on either an inline `string | string[]` field OR on a `@db.rel.from`
// nav prop pointing at an `Array<RoleRecord>`; in the latter case the provider
// auto-injects `controls.$with = [{ name: roleField }]` and walks the joined
// records using the target type's own identifier-field chain.

/**
 * Extended factory mirroring `makeAnnotatedType` but supporting per-field
 * metadata *values* (so we can encode `db.index.unique = ["email_uq"]`
 * groups, `db.rel.from = true`, etc.), a per-field nested annotated type
 * (so we can build `roles: RoleRecord[]` nav props), AND type-level
 * metadata (so we can encode `db.table.preferredId.uniqueIndex = "email_uq"`).
 *
 * We add a new factory rather than mutate the existing one because the
 * existing tests in this file rely on the simpler "annotation name → true"
 * shape, and conflating the two would force every test to spell out the
 * value side.
 */
type PropSpec = {
  /** Each entry is `[annotationName, value]`. Truthy `true` is the default. */
  annotations?: Array<[string, unknown]>;
  /** Provide an explicit nested annotated type — e.g. `RoleType[]` for a rel.from nav prop. */
  fieldType?: TAtscriptAnnotatedType;
};

function makeAnnotatedTypeRich(
  props: Record<string, PropSpec>,
  typeMetadata: Array<[string, unknown]> = [],
): TAtscriptAnnotatedType {
  const propMap = new Map<string, TAtscriptAnnotatedType>();
  for (const [name, spec] of Object.entries(props)) {
    if (spec.fieldType) {
      // Caller provided a fully-built field type (e.g. an `array.of(RoleType)`).
      // Layer the annotations onto its metadata Map.
      const md = spec.fieldType.metadata as Map<string, unknown>;
      for (const [ann, val] of spec.annotations ?? []) md.set(ann, val);
      propMap.set(name, spec.fieldType);
      continue;
    }
    const metadata = new Map<string, unknown>();
    for (const [ann, val] of spec.annotations ?? []) metadata.set(ann, val);
    propMap.set(name, {
      __is_atscript_annotated_type: true,
      type: { kind: "" } as TAtscriptAnnotatedType["type"],
      metadata: metadata as TAtscriptAnnotatedType["metadata"],
      validator: () => ({}) as ReturnType<TAtscriptAnnotatedType["validator"]>,
    });
  }
  const md = new Map<string, unknown>();
  for (const [ann, val] of typeMetadata) md.set(ann, val);
  return {
    __is_atscript_annotated_type: true,
    type: {
      kind: "object",
      props: propMap,
      propsPatterns: [],
      tags: new Set(),
    } as TAtscriptAnnotatedType["type"],
    metadata: md as TAtscriptAnnotatedType["metadata"],
    validator: () => ({}) as ReturnType<TAtscriptAnnotatedType["validator"]>,
  };
}

/**
 * Build an `array.of(targetObjectType)` annotated type — the shape `@db.rel.from`
 * nav props take when the relation is 1:N (`Role[]`). `resolveRelTargetType`
 * descends through `array.of` once.
 */
function makeArrayOf(target: TAtscriptAnnotatedType): TAtscriptAnnotatedType {
  return {
    __is_atscript_annotated_type: true,
    type: { kind: "array", of: target } as unknown as TAtscriptAnnotatedType["type"],
    metadata: new Map() as TAtscriptAnnotatedType["metadata"],
    validator: () => ({}) as ReturnType<TAtscriptAnnotatedType["validator"]>,
  };
}

/** Capture the last `findOne` query for projection / $with assertions. */
interface RecordingTable<T extends object> extends ArbacUserTable<T> {
  lastQuery: Parameters<ArbacUserTable<T>["findOne"]>[0] | undefined;
}
function makeRecordingTable<T extends object>(
  respond: (q: Parameters<ArbacUserTable<T>["findOne"]>[0]) => T | null,
): RecordingTable<T> {
  const t: RecordingTable<T> = {
    lastQuery: undefined,
    async findOne(q) {
      t.lastQuery = q;
      return respond(q);
    },
  };
  return t;
}

describe("AtscriptArbacUserProvider (ISSUE-18)", () => {
  // -- intent 1: preferredId.uniqueIndex fallback ----------------------------
  it("userId chain: falls back to @db.table.preferredId.uniqueIndex when @arbac.userId is absent", async () => {
    // WHY: consumers who address users by a human-readable unique field (e.g.
    // `email`) should not be forced to also tag it `@arbac.userId` when they
    // already declared the unique index. The provider must pick `email` over
    // `id` (the @meta.id) — otherwise auth tokens issued against the email
    // can never resolve a record.
    const userType = makeAnnotatedTypeRich(
      {
        id: { annotations: [["meta.id", true]] },
        email: { annotations: [["db.index.unique", ["email_uq"]]] },
        roles: { annotations: [["arbac.role", true]] },
      },
      [["db.table.preferredId.uniqueIndex", "email_uq"]],
    );
    const table = makeRecordingTable<DemoUser>((q) =>
      q.filter.email === "alice@example.com"
        ? { id: "u-1", username: "alice", roles: ["admin"], tenantId: "t-1" }
        : null,
    );
    class P extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(userType, table);
      }
      override getUserId() {
        return "alice@example.com";
      }
    }
    const p = new P();
    const roles = await inEvent(() => p.getRoles("alice@example.com"));
    expect(roles).toEqual(["admin"]);
    // The filter MUST be keyed by `email`, not `id` — that's the whole point
    // of the preferredId.uniqueIndex fallback.
    expect(table.lastQuery?.filter).toEqual({ email: "alice@example.com" });
    expect(table.lastQuery?.controls?.$select).toEqual({ email: 1, roles: 1 });
  });

  // -- intent 2: @meta.id last fallback --------------------------------------
  it("userId chain: falls back to @meta.id when neither @arbac.userId nor preferredId.uniqueIndex are declared", async () => {
    // WHY: this is the floor of the chain. Removing it would mean every model
    // must opt in to an identifier — but @meta.id is universal in the DB
    // ecosystem, so it's the safe default.
    const userType = makeAnnotatedTypeRich({
      id: { annotations: [["meta.id", true]] },
      roles: { annotations: [["arbac.role", true]] },
    });
    const table = makeRecordingTable<DemoUser>((q) =>
      q.filter.id === "u-1"
        ? { id: "u-1", username: "alice", roles: ["admin"], tenantId: "t-1" }
        : null,
    );
    class P extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(userType, table);
      }
      override getUserId() {
        return "u-1";
      }
    }
    const p = new P();
    await inEvent(() => p.getRoles("u-1"));
    expect(table.lastQuery?.filter).toEqual({ id: "u-1" });
  });

  // -- intent 3: explicit @arbac.userId wins over both -----------------------
  it("userId chain: explicit @arbac.userId wins over preferredId.uniqueIndex and @meta.id", async () => {
    // WHY: priority order is the load-bearing contract. With all three sources
    // present, an explicit `@arbac.userId` MUST win — otherwise consumers
    // can't override the chain when their JWT subject doesn't match the
    // preferred index field.
    const userType = makeAnnotatedTypeRich(
      {
        id: { annotations: [["meta.id", true]] },
        email: { annotations: [["db.index.unique", ["email_uq"]]] },
        username: { annotations: [["arbac.userId", true]] },
        roles: { annotations: [["arbac.role", true]] },
      },
      [["db.table.preferredId.uniqueIndex", "email_uq"]],
    );
    const table = makeRecordingTable<DemoUser>((q) =>
      q.filter.username === "alice"
        ? { id: "u-1", username: "alice", roles: ["admin"], tenantId: "t-1" }
        : null,
    );
    class P extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(userType, table);
      }
      override getUserId() {
        return "alice";
      }
    }
    const p = new P();
    await inEvent(() => p.getRoles("alice"));
    expect(table.lastQuery?.filter).toEqual({ username: "alice" });
  });

  // -- intent 4: multi-role fail-loud ----------------------------------------
  it("constructor throws when more than one field is annotated @arbac.role (fail-loud)", () => {
    // WHY: pre-ISSUE-18, two `@arbac.role` fields would silently union into a
    // single source — which made it impossible to tell at boot time which
    // field was "winning". Throwing surfaces the misconfiguration before the
    // app starts serving requests.
    const userType = makeAnnotatedTypeRich({
      id: { annotations: [["meta.id", true]] },
      roles: { annotations: [["arbac.role", true]] },
      legacyRoles: { annotations: [["arbac.role", true]] },
    });
    class BadProvider extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(userType, {
          async findOne() {
            return null;
          },
        });
      }
      override getUserId() {
        return "ignored";
      }
    }
    expect(() => new BadProvider()).toThrow(/multiple @arbac\.role/i);
  });

  // -- intent 5: inline roles shape ------------------------------------------
  it("inline @arbac.role: projection includes the field and extractRoles reads record[rolesField]", async () => {
    // WHY: the inline shape is the "no join required" path. It MUST appear in
    // the $select projection (so the DB returns it) and extractRoles must
    // walk the raw field value — not invent a $with clause.
    const userType = makeAnnotatedTypeRich({
      id: { annotations: [["meta.id", true]] },
      roles: { annotations: [["arbac.role", true]] },
      tenantId: { annotations: [["arbac.attribute", true]] },
    });
    const stored: DemoUser = {
      id: "u-1",
      username: "alice",
      roles: ["admin", "editor"],
      tenantId: "t-1",
    };
    const table = makeRecordingTable<DemoUser>((q) => (q.filter.id === "u-1" ? stored : null));
    class P extends AtscriptArbacUserProvider<DemoUser> {
      constructor() {
        super(userType, table);
      }
      override getUserId() {
        return "u-1";
      }
    }
    const p = new P();
    const roles = await inEvent(() => p.getRoles("u-1"));
    expect(roles).toEqual(["admin", "editor"]);
    // Inline shape MUST project the roles field via $select; MUST NOT inject $with.
    expect(table.lastQuery?.controls?.$select).toEqual({ id: 1, roles: 1, tenantId: 1 });
    expect(table.lastQuery?.controls?.$with).toBeUndefined();
  });

  // -- intent 6: rel.from roles shape ----------------------------------------
  it("rel.from @arbac.role: provider injects $with and extractRoles walks joined records", async () => {
    // WHY: when roles live in a separate table via `@db.rel.from`, the
    // provider must (a) tell the adapter to materialize the join via $with
    // and (b) NOT add the nav field to $select (the adapter returns joined
    // records out-of-band). extractRoles then walks each joined record and
    // pulls the role identifier — resolved at spec time using the SAME
    // chain as the user id (here: @meta.id on the role target).
    type DemoUserWithJoinedRoles = Omit<DemoUser, "roles"> & {
      roles: Array<{ id: string }>;
    };
    const RoleType = makeAnnotatedTypeRich({
      id: { annotations: [["meta.id", true]] },
      name: {},
    });
    const userType = makeAnnotatedTypeRich({
      id: { annotations: [["meta.id", true]] },
      roles: {
        // `db.rel.from` truthy + array.of(RoleType) → triggers the rel.from branch.
        annotations: [["db.rel.from", true]],
        fieldType: makeArrayOf(RoleType),
      },
      tenantId: { annotations: [["arbac.attribute", true]] },
    });
    // Re-annotate the roles field with @arbac.role on top of @db.rel.from.
    (userType.type as { props: Map<string, TAtscriptAnnotatedType> }).props
      .get("roles")!
      .metadata.set("arbac.role", true);

    const stored: DemoUserWithJoinedRoles = {
      id: "u-1",
      username: "alice",
      roles: [{ id: "admin" }, { id: "editor" }, { id: "admin" }, { id: "" }],
      tenantId: "t-1",
    };
    const table = makeRecordingTable<DemoUserWithJoinedRoles>((q) =>
      q.filter.id === "u-1" ? stored : null,
    );

    class P extends AtscriptArbacUserProvider<DemoUserWithJoinedRoles> {
      constructor() {
        super(userType, table);
      }
      override getUserId() {
        return "u-1";
      }
    }
    const p = new P();
    const roles = await inEvent(() => p.getRoles("u-1"));
    // Dedup + drop-empty applies in the rel.from branch the same as inline.
    expect(roles).toEqual(["admin", "editor"]);
    // The whole point of the rel.from shape: provider asks the adapter to
    // materialize the join (not project the nav field via $select).
    expect(table.lastQuery?.controls?.$with).toEqual([{ name: "roles" }]);
    expect(table.lastQuery?.controls?.$select).toEqual({ id: 1, tenantId: 1 });
    // Belt-and-braces: the joined nav prop is NOT in $select.
    expect(table.lastQuery?.controls?.$select?.roles).toBeUndefined();
  });

  // -- intent 7: multi-attribute merge ---------------------------------------
  it("multiple @arbac.attribute fields: all appear in projection and merge into getAttrs", async () => {
    // WHY: a user record commonly carries multiple ARBAC-relevant attributes
    // (tenantId, region, plan, ...). The projection must enumerate all of
    // them — silently dropping any would create an authorize() rule that
    // evaluates against `undefined` and quietly denies access.
    type MultiAttrUser = {
      id: string;
      tenantId: string;
      region: string;
      plan: string;
      roles: string[];
    };
    const userType = makeAnnotatedTypeRich({
      id: { annotations: [["meta.id", true]] },
      tenantId: { annotations: [["arbac.attribute", true]] },
      region: { annotations: [["arbac.attribute", true]] },
      plan: { annotations: [["arbac.attribute", true]] },
      roles: { annotations: [["arbac.role", true]] },
    });
    const stored: MultiAttrUser = {
      id: "u-1",
      tenantId: "t-1",
      region: "eu",
      plan: "pro",
      roles: ["admin"],
    };
    const table = makeRecordingTable<MultiAttrUser>((q) => (q.filter.id === "u-1" ? stored : null));
    class P extends AtscriptArbacUserProvider<MultiAttrUser> {
      constructor() {
        super(userType, table);
      }
      override getUserId() {
        return "u-1";
      }
    }
    const p = new P();
    const attrs = await inEvent(() => p.getAttrs("u-1"));
    expect(attrs).toEqual({ tenantId: "t-1", region: "eu", plan: "pro" });
    expect(table.lastQuery?.controls?.$select).toEqual({
      id: 1,
      roles: 1,
      tenantId: 1,
      region: 1,
      plan: 1,
    });
  });
});
