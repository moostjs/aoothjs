import type { TMetaResponse } from "@atscript/db";
import { deserializeAnnotatedType } from "@atscript/typescript/utils";
import type { TSerializedAnnotatedType } from "@atscript/typescript/utils";
import { isFieldAllowed } from "@aooth/arbac";
import { describe, expect, it } from "vite-plus/test";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import {
  MAX_INLINED_NODES,
  applyArbacFormOverlay,
  collectMethodNames,
  pruneMetaByVisibility,
} from "./meta-projection";
import { isScopedFieldVisible } from "./request-scopes";
import {
  buildScopeVisibility,
  collectWithGrantNames,
  isMetaFieldVisible,
  unionScopeProjection,
} from "./visibility";
import type { ArbacRelationResolution, MetaVisibility, VisibilityTableSource } from "./visibility";

// ── Fixtures ───────────────────────────────────────────────────────────────

const NONE: ReadonlySet<string> = new Set();

function vis(
  allowed: Record<string, 0 | 1>,
  alwaysVisible: ReadonlySet<string> = NONE,
  withGrants: ReadonlySet<string> = NONE,
): MetaVisibility {
  return { allowed, alwaysVisible, withGrants };
}

/** Minimal serialized node helpers — only the fields the pruner reads. */
function leaf(): TSerializedAnnotatedType {
  return { $v: 2, type: { kind: "", designType: "string", tags: [] }, metadata: {} };
}
function obj(props: Record<string, TSerializedAnnotatedType>): TSerializedAnnotatedType {
  return { $v: 2, type: { kind: "object", props, propsPatterns: [], tags: [] }, metadata: {} };
}
function arr(of: TSerializedAnnotatedType): TSerializedAnnotatedType {
  return { $v: 2, type: { kind: "array", of, tags: [] }, metadata: {} };
}

/** A users-table-shaped meta envelope (the field-tested disclosure scenario). */
function usersMeta(): TMetaResponse {
  return {
    searchable: false,
    vectorSearchable: false,
    searchIndexes: [],
    primaryKeys: ["id"],
    preferredId: ["id"],
    relations: [
      { name: "department", direction: "to", isArray: false },
      { name: "auditEvents", direction: "from", isArray: true },
    ],
    fields: {
      id: { sortable: true, filterable: true },
      username: { sortable: true, filterable: true },
      "password.hash": { sortable: false, filterable: false },
      "password.history": { sortable: false, filterable: false },
      "account.lockReason": { sortable: false, filterable: true },
      version: { sortable: false, filterable: false },
    },
    type: obj({
      id: leaf(),
      username: leaf(),
      password: obj({ hash: leaf(), history: arr(leaf()) }),
      account: obj({ lockReason: leaf() }),
      version: leaf(),
      department: obj({ name: leaf() }),
      auditEvents: arr(obj({ kind: leaf() })),
    }),
    actions: [],
    crud: { query: [] },
    versionColumn: "version",
  };
}

// ── unionScopeProjection ───────────────────────────────────────────────────

describe("unionScopeProjection", () => {
  it("no scopes → undefined (unrestricted)", () => {
    expect(unionScopeProjection([])).toBeUndefined();
  });

  it("any scope without a projection is a universal grant → undefined", () => {
    const scopes: ArbacDbScope[] = [{ projection: { username: 1 } }, { filter: { a: 1 } }];
    expect(unionScopeProjection(scopes)).toBeUndefined();
  });

  it("include-mode scopes union their whitelists", () => {
    const scopes: ArbacDbScope[] = [{ projection: { username: 1 } }, { projection: { id: 1 } }];
    expect(unionScopeProjection(scopes)).toEqual({ id: 1, username: 1 });
  });

  it("exclude-mode scopes intersect their denials (additive across roles)", () => {
    const scopes: ArbacDbScope[] = [
      { projection: { secret: 0, internal: 0 } },
      { projection: { secret: 0 } },
    ];
    expect(unionScopeProjection(scopes)).toEqual({ secret: 0 });
  });
});

// ── isMetaFieldVisible ─────────────────────────────────────────────────────

describe("isMetaFieldVisible", () => {
  it("include mode: listed fields, their subtrees, and include-bearing parents are visible", () => {
    const v = vis({ username: 1, "password.hash": 1 });
    expect(isMetaFieldVisible("username", v)).toBe(true);
    // Parent of an included child stays visible (it must hold the child).
    expect(isMetaFieldVisible("password", v)).toBe(true);
    expect(isMetaFieldVisible("password.hash", v)).toBe(true);
    // Sibling under the same parent is NOT.
    expect(isMetaFieldVisible("password.history", v)).toBe(false);
    expect(isMetaFieldVisible("account.lockReason", v)).toBe(false);
  });

  it("exclude mode: excluded paths and their subtrees vanish", () => {
    const v = vis({ password: 0 });
    expect(isMetaFieldVisible("username", v)).toBe(true);
    expect(isMetaFieldVisible("password", v)).toBe(false);
    expect(isMetaFieldVisible("password.hash", v)).toBe(false);
  });

  it("alwaysVisible identifiers pass regardless of the union", () => {
    const v = vis({ username: 1 }, new Set(["id"]));
    expect(isMetaFieldVisible("id", v)).toBe(true);
  });

  it("hand-built visibility without `relation`: granted paths pass through (legacy)", () => {
    const v = vis({ username: 1 }, NONE, new Set(["department"]));
    expect(isMetaFieldVisible("department", v)).toBe(true);
    expect(isMetaFieldVisible("department.name", v)).toBe(true);
    expect(isMetaFieldVisible("auditEvents.kind", v)).toBe(false);
  });
});

// ── buildScopeVisibility / isScopedFieldVisible (with sub-scopes) ─────────

describe("buildScopeVisibility — with-granted relation paths", () => {
  // department → org, each a table whose PK is `id` (org's preferredId: `code`).
  const orgTable: VisibilityTableSource = { primaryKeys: ["id"], preferredId: ["code"] };
  const deptTable: VisibilityTableSource = {
    primaryKeys: ["id"],
    preferredId: ["id"],
    relatedTable: (nav) => (nav === "org" ? orgTable : undefined),
  };
  const usersTable: VisibilityTableSource = {
    primaryKeys: ["id"],
    preferredId: ["id"],
    relatedTable: (nav) => (nav === "department" ? deptTable : undefined),
  };

  const scopes: ArbacDbScope[] = [
    {
      projection: { secret: 0 },
      with: {
        department: { projection: { name: 1 }, with: { org: { projection: { budget: 0 } } } },
      },
    },
  ];

  it("checks rel.x against the sub-scope union, recursively; related identifiers stay visible", () => {
    const v = buildScopeVisibility(scopes, usersTable);
    expect(isMetaFieldVisible("department", v)).toBe(true);
    expect(isMetaFieldVisible("department.name", v)).toBe(true);
    expect(isMetaFieldVisible("department.budgetCode", v)).toBe(false);
    expect(isMetaFieldVisible("department.id", v)).toBe(true); // related PK
    expect(isMetaFieldVisible("department.org", v)).toBe(true); // nested grant
    expect(isMetaFieldVisible("department.org.name", v)).toBe(true);
    expect(isMetaFieldVisible("department.org.budget", v)).toBe(false);
    expect(isMetaFieldVisible("department.org.code", v)).toBe(true); // related preferredId
    expect(isMetaFieldVisible("secret", v)).toBe(false);
  });

  it("sub-scopes union across roles like top-level projections (broader wins)", () => {
    const v = buildScopeVisibility(
      [
        { with: { department: { projection: { name: 1 } } } },
        { with: { department: { projection: { head: 1 } } } },
      ],
      usersTable,
    );
    expect(isMetaFieldVisible("department.name", v)).toBe(true);
    expect(isMetaFieldVisible("department.head", v)).toBe(true);
    expect(isMetaFieldVisible("department.budget", v)).toBe(false);
    // A sub-scope without a projection is a universal grant for the relation.
    const open = buildScopeVisibility(
      [{ with: { department: { projection: { name: 1 } } } }, { with: { department: {} } }],
      usersTable,
    );
    expect(isMetaFieldVisible("department.budget", open)).toBe(true);
  });

  it("restricts joined paths even when the own-field projection is unrestricted", () => {
    const v = buildScopeVisibility(
      [{ with: { department: { projection: { budget: 0 } } } }],
      usersTable,
    );
    expect(v.allowed).toEqual({});
    expect(isMetaFieldVisible("anything", v)).toBe(true);
    expect(isMetaFieldVisible("department.budget", v)).toBe(false);
  });

  it("isScopedFieldVisible: no scopes → visible; legacy identifier-set arg still enforces sub-scopes", () => {
    expect(isScopedFieldVisible([], "department.budget", new Set())).toBe(true);
    const ids = new Set(["id"]);
    expect(isScopedFieldVisible(scopes, "department.name", ids)).toBe(true);
    expect(isScopedFieldVisible(scopes, "department.budget", ids)).toBe(false);
  });
});

// ── collectWithGrantNames ──────────────────────────────────────────────────

describe("collectWithGrantNames", () => {
  it("collects relation names across scopes; silence collects nothing", () => {
    const scopes: ArbacDbScope[] = [
      { with: { department: {} } },
      { with: { auditEvents: { projection: { kind: 1 } } } },
      { projection: { username: 1 } },
    ];
    expect([...collectWithGrantNames(scopes)].toSorted()).toEqual(["auditEvents", "department"]);
    expect(collectWithGrantNames([{ projection: { a: 1 } }]).size).toBe(0);
  });
});

// ── pruneMetaByVisibility ──────────────────────────────────────────────────

describe("pruneMetaByVisibility", () => {
  const INCLUDE_14ISH = vis({ username: 1 }, new Set(["id"]));

  it("include-mode whitelist: hidden field NAMES vanish from fields + type (the live disclosure)", () => {
    const out = pruneMetaByVisibility(usersMeta(), INCLUDE_14ISH);
    // Capability map: only the whitelist + identifiers survive.
    expect(Object.keys(out.fields).toSorted()).toEqual(["id", "username"]);
    // Serialized type: the secret-bearing prop subtrees are GONE — a dynamic
    // client building its column picker from `type` can no longer offer them.
    const props = (out.type.type as { props: Record<string, unknown> }).props;
    expect(Object.keys(props).toSorted()).toEqual(["id", "username"]);
  });

  it("nested include keeps the parent with ONLY the included child inside", () => {
    const out = pruneMetaByVisibility(usersMeta(), vis({ "password.hash": 1 }, new Set(["id"])));
    expect(Object.keys(out.fields).toSorted()).toEqual(["id", "password.hash"]);
    const props = (out.type.type as { props: Record<string, { type: { props?: object } }> }).props;
    expect(Object.keys(props).toSorted()).toEqual(["id", "password"]);
    expect(Object.keys(props.password.type.props ?? {})).toEqual(["hash"]);
  });

  it("exclude mode drops exactly the denied subtree", () => {
    const out = pruneMetaByVisibility(usersMeta(), vis({ password: 0 }));
    expect(Object.keys(out.fields).toSorted()).toEqual([
      "account.lockReason",
      "id",
      "username",
      "version",
    ]);
    const props = (out.type.type as { props: Record<string, unknown> }).props;
    expect(props.password).toBeUndefined();
    expect(props.account).toBeDefined();
  });

  it("relations survive via projection OR an explicit with-grant; others vanish", () => {
    const grant = vis({ username: 1 }, new Set(["id"]), new Set(["department"]));
    const out = pruneMetaByVisibility(usersMeta(), grant);
    expect(out.relations.map((r) => r.name)).toEqual(["department"]);
    // The with-granted relation's nav prop also survives in the type — whole,
    // since its CONTENT is governed by the with sub-scope at query time.
    const props = (out.type.type as { props: Record<string, unknown> }).props;
    expect(props.department).toBeDefined();
    expect(props.auditEvents).toBeUndefined();
  });

  it("versionColumn is dropped when the OCC column itself is hidden", () => {
    const hidden = pruneMetaByVisibility(usersMeta(), INCLUDE_14ISH);
    expect(hidden.versionColumn).toBeUndefined();
    const kept = pruneMetaByVisibility(usersMeta(), vis({ username: 1, version: 1 }));
    expect(kept.versionColumn).toBe("version");
  });

  it("NEVER mutates the input envelope (the base controller caches it)", () => {
    const meta = usersMeta();
    const fieldsBefore = JSON.stringify(meta);
    pruneMetaByVisibility(meta, INCLUDE_14ISH);
    expect(JSON.stringify(meta)).toBe(fieldsBefore);
  });
});

// ── writeOnly stamping (writable-but-unreadable fields) ────────────────────

describe("pruneMetaByVisibility — with-granted nav types", () => {
  it("prunes a granted relation's nav type by its sub-scope; ungranted visible ones stay whole", () => {
    const meta = usersMeta();
    (meta.type.type as { props: Record<string, unknown> }).props.department = obj({
      id: leaf(),
      name: leaf(),
      budget: leaf(),
    });
    const v = buildScopeVisibility(
      [{ projection: { password: 0 }, with: { department: { projection: { name: 1 } } } }],
      { primaryKeys: ["id"], preferredId: ["id"] },
    );
    const out = pruneMetaByVisibility(meta, v);
    type Node = { type: { props: Record<string, unknown> } };
    const props = (out.type as unknown as Node).type.props as Record<string, Node>;
    const dept = props.department.type.props;
    // No `relatedTable`: the related PK is not exempt, only the sub-scope whitelist survives.
    expect(Object.keys(dept)).toEqual(["name"]);
    // Ungranted, projection-visible relation: whole.
    expect(props.auditEvents).toEqual(arr(obj({ kind: leaf() })));
  });
});

describe("pruneMetaByVisibility — writeOnly stamping", () => {
  const READ_USERNAME_ONLY = { id: 1, username: 1 } as Record<string, 0 | 1>;

  function visW(writable: MetaVisibility["writable"]): MetaVisibility {
    return { allowed: READ_USERNAME_ONLY, alwaysVisible: NONE, withGrants: NONE, writable };
  }

  it("keeps a writable-but-unreadable field as writeOnly instead of pruning it", () => {
    const out = pruneMetaByVisibility(usersMeta(), visW(new Set(["password"])));
    expect(out.fields["password.hash"]).toEqual({
      sortable: false,
      filterable: false,
      writeOnly: true,
    });
    const props = (out.type.type as unknown as { props: Record<string, TSerializedAnnotatedType> })
      .props;
    expect(props.password).toBeDefined();
    expect(props.password.metadata["db.writeOnly"]).toBe(true);
    // Subtree kept whole — clients need the full shape to write it.
    expect((props.password.type as { props: Record<string, unknown> }).props.hash).toBeDefined();
  });

  it("still prunes fields outside both read and write grants", () => {
    const out = pruneMetaByVisibility(usersMeta(), visW(new Set(["password"])));
    expect(out.fields["account.lockReason"]).toBeUndefined();
    const props = (out.type.type as unknown as { props: Record<string, TSerializedAnnotatedType> })
      .props;
    expect(props.account).toBeUndefined();
  });

  it('"all" writable stamps every unreadable field', () => {
    const out = pruneMetaByVisibility(usersMeta(), visW("all"));
    expect(out.fields["account.lockReason"]?.writeOnly).toBe(true);
    expect(out.fields.username.writeOnly).toBeUndefined();
  });

  it("no writable set → identical to plain pruning", () => {
    const plain = pruneMetaByVisibility(usersMeta(), visW(undefined));
    expect(plain.fields["password.hash"]).toBeUndefined();
  });

  it("an unreadable relation is a write affordance only when opted into nestedWrites", () => {
    type Props = Record<string, TSerializedAnnotatedType>;
    const propsOf = (out: TMetaResponse) => (out.type.type as unknown as { props: Props }).props;
    // Unrestricted writes alone never make a relation writable.
    const denied = propsOf(pruneMetaByVisibility(usersMeta(), visW("all")));
    expect(denied.department).toBeUndefined();
    expect(denied.auditEvents).toBeUndefined();

    const out = propsOf(
      pruneMetaByVisibility(usersMeta(), {
        ...visW("all"),
        nestedWrites: new Set(["department"]),
      }),
    );
    expect(out.department.metadata["db.writeOnly"]).toBe(true);
    expect(out.auditEvents).toBeUndefined();
    // A write whitelist must still cover the relation.
    const listed = propsOf(
      pruneMetaByVisibility(usersMeta(), {
        ...visW(new Set(["password"])),
        nestedWrites: new Set(["department"]),
      }),
    );
    expect(listed.department).toBeUndefined();
  });

  it("paths through a relation are never stamped writable without nestedWrites", () => {
    const meta = usersMeta();
    meta.fields["department.name"] = { sortable: false, filterable: false };
    const relationNames = new Set(["department", "auditEvents"]);
    const out = pruneMetaByVisibility(meta, { ...visW("all"), relationNames });
    expect(out.fields["department.name"]).toBeUndefined();
    expect(out.fields["account.lockReason"]?.writeOnly).toBe(true);
    const opted = pruneMetaByVisibility(meta, {
      ...visW("all"),
      relationNames,
      nestedWrites: new Set(["department"]),
    });
    expect(opted.fields["department.name"]?.writeOnly).toBe(true);
  });

  it("ancestor grants cover nested paths (credit.credentials covers .user)", () => {
    const out = pruneMetaByVisibility(usersMeta(), visW(new Set(["password"])));
    // "password.history" sits under the "password" grant.
    expect(out.fields["password.history"]?.writeOnly).toBe(true);
  });
});

describe("collectMethodNames", () => {
  it("collects methods across the prototype chain without firing accessors", () => {
    class Base {
      // Mimics moost-db's view-guarded `.table` getter.
      get table(): never {
        throw new Error(".table is only available for table-bound controllers.");
      }
      baseMethod(): void {}
    }
    class Derived extends Base {
      derivedMethod(): void {}
    }
    const instance = new Derived() as Derived & { own?: () => void };
    instance.own = () => {};

    const names = collectMethodNames(instance);
    expect(names).toEqual(expect.arrayContaining(["baseMethod", "derivedMethod", "own"]));
    expect(names).not.toContain("table");
    expect(names).not.toContain("constructor");
  });
});

describe("buildScopeVisibility — precompiled isAllowed matches isFieldAllowed", () => {
  const paths = ["a", "a.b", "a.b.c", "a.c", "ab", "b", "b.x", "constructor", "x.y.z"];
  it.each([
    [{ a: 1 }],
    [{ "a.b": 1 }],
    [{ "a.b.c": 1, b: 1 }],
    [{ a: 0 }],
    [{ "a.b": 0, "x.y": 0 }],
    [{}],
  ] as Array<[Record<string, 0 | 1>]>)("%j", (projection) => {
    const v = buildScopeVisibility([{ projection }], undefined);
    for (const p of paths) expect(v.isAllowed!(p), p).toBe(isFieldAllowed(p, projection));
  });
});

// ── 0.1.72 read-side policy ────────────────────────────────────────────────

describe("pruneMetaByVisibility — writable descendant under a hidden parent", () => {
  it("keeps the hidden parent with ONLY its writable leaves, stamped writeOnly", () => {
    const v: MetaVisibility = {
      allowed: { id: 1, username: 1 },
      alwaysVisible: NONE,
      withGrants: NONE,
      writable: new Set(["password.hash"]),
    };
    const out = pruneMetaByVisibility(usersMeta(), v);
    expect(out.fields["password.hash"]?.writeOnly).toBe(true);
    expect(out.fields["password.history"]).toBeUndefined();
    const props = (out.type.type as unknown as { props: Record<string, TSerializedAnnotatedType> })
      .props;
    expect(props.password.metadata["db.writeOnly"]).toBe(true);
    const inner = (
      props.password.type as unknown as { props: Record<string, TSerializedAnnotatedType> }
    ).props;
    expect(Object.keys(inner)).toEqual(["hash"]);
    expect(inner.hash.metadata["db.writeOnly"]).toBe(true);
    expect(props.account).toBeUndefined();
  });
});

// `settings` is a JSON column; `copy` is derived from `settings.key`.
function jsonTable(storage: "json" | "column"): VisibilityTableSource {
  return {
    primaryKeys: ["id"],
    preferredId: ["id"],
    flatMap: new Map(
      ["id", "title", "settings", "settings.key", "settings.theme", "copy"].map((p) => [p, {}]),
    ),
    fieldDescriptors: [{ path: "copy", derived: { sourcePath: "settings.key" } }],
    jsonParents: new Set(storage === "json" ? ["settings"] : []),
  };
}

describe("buildScopeVisibility — derived columns and atomic JSON columns", () => {
  it("atomic JSON: an excluded leaf hides the whole column", () => {
    const v = buildScopeVisibility([{ projection: { "settings.key": 0 } }], jsonTable("json"));
    expect(v.allowed).toEqual({ settings: 0, copy: 0 });
    for (const p of ["settings", "settings.theme", "settings.key", "copy"]) {
      expect(isMetaFieldVisible(p, v), p).toBe(false);
    }
    expect(isMetaFieldVisible("title", v)).toBe(true);
  });

  it("atomic JSON: a whitelisted leaf alone does not reveal the column", () => {
    const v = buildScopeVisibility([{ projection: { "settings.theme": 1 } }], jsonTable("json"));
    expect(v.allowed).toEqual({ id: 1 });
    expect(isMetaFieldVisible("settings", v)).toBe(false);
    expect(isMetaFieldVisible("settings.theme", v)).toBe(false);
  });

  it("addressable JSON (document adapters) keeps sub-path precision", () => {
    const v = buildScopeVisibility([{ projection: { "settings.key": 0 } }], jsonTable("column"));
    expect(isMetaFieldVisible("settings", v)).toBe(true);
    expect(isMetaFieldVisible("settings.theme", v)).toBe(true);
    expect(isMetaFieldVisible("settings.key", v)).toBe(false);
    // …and the derived copy follows its hidden source.
    expect(isMetaFieldVisible("copy", v)).toBe(false);
    expect(v.allowed).toEqual({ "settings.key": 0, copy: 0 });
  });

  it("derived: a whitelisted derived field whose source is not visible is dropped", () => {
    const v = buildScopeVisibility([{ projection: { title: 1, copy: 1 } }], jsonTable("column"));
    expect(v.allowed).toEqual({ title: 1 });
    expect(isMetaFieldVisible("copy", v)).toBe(false);
    const withSource = buildScopeVisibility(
      [{ projection: { title: 1, copy: 1, "settings.key": 1 } }],
      jsonTable("column"),
    );
    expect(isMetaFieldVisible("copy", withSource)).toBe(true);
  });
});

describe("buildScopeVisibility — undeclared relations (inherit-target)", () => {
  const userTable: VisibilityTableSource = { primaryKeys: ["id"], preferredId: ["id"] };
  const taskTable: VisibilityTableSource = {
    primaryKeys: ["id"],
    preferredId: ["id"],
    relations: new Map([["owner", {}]]),
    relatedTable: (nav) => (nav === "owner" ? userTable : undefined),
  };

  it("unresolved → hidden, even for an unrestricted parent grant", () => {
    const v = buildScopeVisibility([{}], taskTable);
    expect(isMetaFieldVisible("owner", v)).toBe(false);
    expect(isMetaFieldVisible("owner.name", v)).toBe(false);
    expect(isMetaFieldVisible("title", v)).toBe(true);
    expect(isScopedFieldVisible([], "owner", taskTable)).toBe(false);
  });

  it("resolved → the related grant's visibility; the parent projection still gates the name", () => {
    const resolution: ArbacRelationResolution = new Map([
      ["owner", buildScopeVisibility([{ projection: { salary: 0 } }], userTable)],
    ]);
    const v = buildScopeVisibility([{}], taskTable, { relations: resolution });
    expect(isMetaFieldVisible("owner", v)).toBe(true);
    expect(isMetaFieldVisible("owner.name", v)).toBe(true);
    expect(isMetaFieldVisible("owner.salary", v)).toBe(false);
    const gated = buildScopeVisibility([{ projection: { title: 1 } }], taskTable, {
      relations: resolution,
    });
    expect(isMetaFieldVisible("owner", gated)).toBe(false);
  });

  it("hidden (null) → hidden; a declared with.<rel> ignores the resolution", () => {
    const hidden: ArbacRelationResolution = new Map([["owner", null]]);
    expect(
      isMetaFieldVisible("owner", buildScopeVisibility([{}], taskTable, { relations: hidden })),
    ).toBe(false);
    const declared = buildScopeVisibility(
      [{ with: { owner: { projection: { name: 1 } } } }, {}],
      taskTable,
      { relations: hidden },
    );
    expect(isMetaFieldVisible("owner.name", declared)).toBe(true);
    expect(isMetaFieldVisible("owner.salary", declared)).toBe(false);
  });
});

describe("pruneMetaByVisibility — an unresolvable ui.valueHelp binding fails closed", () => {
  it("a binding whose target throws on resolution is stripped (was kept)", () => {
    const entry = {
      metadata: {
        get: (key: string) =>
          key === "ui.valueHelp"
            ? {
                target: () => {
                  throw new Error("unresolved");
                },
                field: "code",
              }
            : undefined,
      },
    };
    const bound = leaf();
    bound.metadata = { "ui.valueHelp": { field: "code" } };
    const meta = {
      ...usersMeta(),
      type: obj({ id: leaf(), color: bound }),
      relations: [],
    } as unknown as TMetaResponse;
    const table = {
      primaryKeys: ["id"],
      preferredId: ["id"],
      type: {},
      flatMap: new Map([["color", entry]]),
    } as unknown as VisibilityTableSource;
    const v = { ...buildScopeVisibility([{}], table), table };
    const out = pruneMetaByVisibility(meta, v, new Map());
    const props = (out.type.type as unknown as { props: Record<string, TSerializedAnnotatedType> })
      .props;
    expect(props.color).toBeDefined();
    expect(props.color.metadata["ui.valueHelp"]).toBeUndefined();
  });
});

// ── $ref entries (a named type used more than once) ────────────────────────

describe("pruneMetaByVisibility — $ref entries with own metadata", () => {
  const addrBody = () =>
    obj({
      street: { ...leaf(), metadata: { "meta.label": "Street" } },
      secret: { ...leaf(), metadata: { "meta.label": "Secret" } },
    });
  /** `home` carries the named type's body; `work` is an own-metadata `$ref` to it. */
  function twiceUsedMeta(): TMetaResponse {
    const meta = usersMeta();
    meta.fields = {
      id: { sortable: true, filterable: true },
      "home.street": { sortable: false, filterable: true },
      "home.secret": { sortable: false, filterable: true },
      "work.street": { sortable: false, filterable: true },
      "work.secret": { sortable: false, filterable: true },
    };
    meta.relations = [];
    meta.type = obj({
      id: leaf(),
      home: { ...addrBody(), id: "Addr", metadata: { "meta.label": "Home" } },
      work: {
        $v: 2,
        type: { kind: "$ref", id: "Addr", own: true },
        metadata: { "meta.label": "Work", "ui.hint": "work-only" },
        optional: true,
      },
    });
    return meta;
  }
  type Props = Record<string, TSerializedAnnotatedType>;
  const propsOf = (n: TSerializedAnnotatedType) => (n.type as unknown as { props: Props }).props;

  it("does not leak a path hidden at the $ref position through the shared body", () => {
    const out = pruneMetaByVisibility(
      twiceUsedMeta(),
      vis({ "home.street": 1, "home.secret": 1, "work.street": 1 }, new Set(["id"])),
    );
    const json = JSON.stringify(out.type);
    const work = propsOf(out.type).work;
    // work.secret is hidden: whichever way `work` is represented, no 'Secret' body may hang off it.
    const workJson = JSON.stringify(work);
    expect(workJson).not.toContain("Secret");
    expect(Object.keys(propsOf(work))).toEqual(["street"]);
    // The first use keeps both of its visible fields.
    expect(Object.keys(propsOf(propsOf(out.type).home)).toSorted()).toEqual(["secret", "street"]);
    expect(work.metadata["meta.label"]).toBe("Work");
    expect(work.metadata["ui.hint"]).toBe("work-only");
    expect(json).toContain("Street");
  });

  it("keeps a visible $ref resolvable when its first-use body is hidden", () => {
    const out = pruneMetaByVisibility(twiceUsedMeta(), vis({ "work.street": 1 }, new Set(["id"])));
    const props = propsOf(out.type);
    expect(props.home).toBeUndefined();
    const work = props.work;
    expect(work.metadata["meta.label"]).toBe("Work");
    // No dangling `$ref`: the body is present at the surviving use, minus hidden fields.
    expect(work.type.kind).toBe("object");
    expect(Object.keys(propsOf(work))).toEqual(["street"]);
    expect(JSON.stringify(out.type)).not.toContain("Secret");
  });

  it("never throws on a $ref nested in arrays, unions, or an unknown id", () => {
    const meta = twiceUsedMeta();
    meta.type = obj({
      id: leaf(),
      list: arr({
        $v: 2,
        type: { kind: "$ref", id: "Missing", own: true },
        metadata: {},
      }),
    });
    expect(() => pruneMetaByVisibility(meta, vis({ list: 1 }, new Set(["id"])))).not.toThrow();
  });
});

// ── inlined copies: unique ids + bounded blow-up ───────────────────────────

describe("pruneMetaByVisibility — inlined $ref copies", () => {
  type Props = Record<string, TSerializedAnnotatedType>;
  const propsOf = (n: TSerializedAnnotatedType) => (n.type as unknown as { props: Props }).props;
  const refTo = (id: string, own = false): TSerializedAnnotatedType => ({
    $v: 2,
    type: { kind: "$ref", id, ...(own ? { own: true } : {}) },
    metadata: {},
  });
  const ids = (n: unknown, out: string[] = []): string[] => {
    if (Array.isArray(n)) n.forEach((x) => ids(x, out));
    else if (n && typeof n === "object") {
      const o = n as Record<string, unknown>;
      if (typeof o.id === "string" && o.kind === undefined) out.push(o.id);
      Object.values(o).forEach((x) => ids(x, out));
    }
    return out;
  };
  const refIds = (n: unknown, out: string[] = []): string[] => {
    if (Array.isArray(n)) n.forEach((x) => refIds(x, out));
    else if (n && typeof n === "object") {
      const o = n as Record<string, unknown>;
      if (o.kind === "$ref") out.push(o.id as string);
      Object.values(o).forEach((x) => refIds(x, out));
    }
    return out;
  };

  it("gives each inlined copy a unique id and points its back-ref at its own copy", () => {
    // Node = { name, secret, children: Node[] } used at `home` (body) and `work` ($ref).
    const body: TSerializedAnnotatedType = {
      ...obj({
        name: { ...leaf(), metadata: { "meta.label": "Name" } },
        secret: { ...leaf(), metadata: { "meta.label": "Secret" } },
        children: arr(refTo("Node")),
      }),
      id: "Node",
    };
    const meta = usersMeta();
    meta.relations = [];
    meta.fields = { id: { sortable: true, filterable: true } };
    meta.type = obj({ id: leaf(), home: body, work: refTo("Node") });
    const out = pruneMetaByVisibility(
      meta,
      vis(
        {
          "home.name": 1,
          "home.secret": 1,
          "home.children": 1,
          "work.name": 1,
          "work.children": 1,
        },
        new Set(["id"]),
      ),
    );
    const { home, work } = propsOf(out.type);
    expect(home.id).toBeDefined();
    expect(work.id).toBeDefined();
    expect(home.id).not.toBe(work.id);
    expect(new Set(ids(out.type)).size).toBe(ids(out.type).length);
    const backRef = (n: TSerializedAnnotatedType) =>
      (propsOf(n).children.type as unknown as { of: { type: { id: string } } }).of.type.id;
    expect(backRef(home)).toBe(home.id);
    expect(backRef(work)).toBe(work.id);
    // Visibility differs per path.
    expect(Object.keys(propsOf(home)).toSorted()).toEqual(["children", "name", "secret"]);
    expect(Object.keys(propsOf(work)).toSorted()).toEqual(["children", "name"]);
    // Every remaining $ref resolves to a retained id.
    const known = new Set(ids(out.type));
    for (const r of refIds(out.type)) expect(known.has(r)).toBe(true);
  });

  /** Each level is `{ a: [L(i+1) body, $ref L(i+1)] }` (a union, so the path stays `a.a.a…`); the bottom holds `secret`. */
  function dagMeta(depth: number): TMetaResponse {
    const level = (i: number): TSerializedAnnotatedType => {
      if (i === depth) {
        return {
          ...obj({ secret: { ...leaf(), metadata: { "meta.label": "Secret" } }, v: leaf() }),
          id: `L${i}`,
        };
      }
      const union = {
        $v: 2,
        type: { kind: "union", items: [level(i + 1), refTo(`L${i + 1}`)], tags: [] },
        metadata: {},
      } as unknown as TSerializedAnnotatedType;
      return { ...obj({ a: union }), id: `L${i}` };
    };
    const meta = usersMeta();
    meta.relations = [];
    meta.fields = { id: { sortable: true, filterable: true } };
    meta.type = obj({ id: leaf(), root: level(0) });
    return meta;
  }
  const secretPath = (depth: number) => `root${".a".repeat(depth)}.secret`;
  const countNodes = (n: unknown): number =>
    Array.isArray(n)
      ? n.reduce((s: number, x) => s + countNodes(x), 0)
      : n && typeof n === "object"
        ? 1 + Object.values(n).reduce((s: number, x) => s + countNodes(x), 0)
        : 0;

  it("bounds a DAG schema that would inline exponentially", () => {
    const t0 = Date.now();
    const out = pruneMetaByVisibility(dagMeta(24), vis({ root: 1 }, new Set(["id"])));
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(countNodes(out.type)).toBeLessThan(MAX_INLINED_NODES * 40);
  });

  it("fails closed past the budget: dropped regions carry no body, none unpruned", () => {
    const depth = 24;
    const out = pruneMetaByVisibility(
      dagMeta(depth),
      vis({ [secretPath(depth)]: 0 }, new Set(["id"])),
    );
    expect(JSON.stringify(out.type)).not.toContain("Secret");
    // Budget really bit: the full 2^24 expansion is not there, and no dangling $ref.
    const known = new Set(ids(out.type));
    for (const r of refIds(out.type)) expect(known.has(r)).toBe(true);
  });

  it("a small DAG stays fully inlined (no stripping under the budget)", () => {
    const out = pruneMetaByVisibility(dagMeta(3), vis({ root: 1 }, new Set(["id"])));
    const json = JSON.stringify(out.type);
    expect(json).not.toContain('"$ref"');
  });
});

// ── round trip: serialize → ARBAC overlay → real client deserializer ───────

describe("pruneMetaByVisibility — client round trip (deserializeAnnotatedType)", () => {
  const refTo = (
    id: string,
    extra: Partial<TSerializedAnnotatedType> = {},
  ): TSerializedAnnotatedType => ({
    $v: 2,
    type: { kind: "$ref", id, own: true },
    metadata: {},
    ...extra,
  });
  const label = (l: string): TSerializedAnnotatedType => ({
    ...leaf(),
    metadata: { "meta.label": l },
  });
  const addr = (
    extra: Record<string, TSerializedAnnotatedType> = {},
  ): TSerializedAnnotatedType => ({
    ...obj({ street: label("Street"), secret: label("Secret"), ...extra }),
    id: "Addr",
    metadata: { "meta.label": "Home" },
  });
  function metaOf(type: TSerializedAnnotatedType): TMetaResponse {
    const m = usersMeta();
    m.relations = [];
    m.fields = { id: { sortable: true, filterable: true } };
    m.type = type;
    return m;
  }
  /** Project, then deserialize exactly as the client does (through JSON). */
  function client(type: TSerializedAnnotatedType, v: MetaVisibility) {
    const out = pruneMetaByVisibility(metaOf(type), v);
    return deserializeAnnotatedType(JSON.parse(JSON.stringify(out.type))) as any;
  }
  const keys = (n: any) =>
    [...n.type.props.keys()].toSorted((a: string, b: string) => a.localeCompare(b));

  it("a named type used twice keeps each path's own visibility on the client", () => {
    const t = obj({
      id: leaf(),
      home: addr(),
      work: refTo("Addr", { metadata: { "meta.label": "Work" }, optional: true }),
    });
    // work.secret hidden, home.secret visible.
    const a = client(t, vis({ "work.secret": 0 }, new Set(["id"])));
    expect(keys(a.type.props.get("home"))).toEqual(["secret", "street"]);
    expect(keys(a.type.props.get("work"))).toEqual(["street"]);
    // home.secret hidden, work.secret visible (the reverse leak).
    const b = client(t, vis({ "home.secret": 0 }, new Set(["id"])));
    expect(keys(b.type.props.get("home"))).toEqual(["street"]);
    expect(keys(b.type.props.get("work"))).toEqual(["secret", "street"]);
  });

  it("own-metadata label and optionality survive per path", () => {
    const t = obj({
      id: leaf(),
      home: addr(),
      work: refTo("Addr", { metadata: { "meta.label": "Work" }, optional: true }),
    });
    const c = client(t, vis({}, new Set(["id"])));
    const home = c.type.props.get("home");
    const work = c.type.props.get("work");
    expect(home.metadata.get("meta.label")).toBe("Home");
    expect(work.metadata.get("meta.label")).toBe("Work");
    expect(home.optional).toBeFalsy();
    expect(work.optional).toBe(true);
  });

  it("a recursive type on two paths resolves each back-ref to its own copy", () => {
    const node: TSerializedAnnotatedType = {
      ...obj({
        name: label("Name"),
        secret: label("Secret"),
        children: { $v: 2, type: { kind: "array", of: refTo("Node"), tags: [] }, metadata: {} },
      }),
      id: "Node",
    };
    const t = obj({ id: leaf(), home: node, work: refTo("Node") });
    const c = client(t, vis({ "work.secret": 0 }, new Set(["id"])));
    const home = c.type.props.get("home");
    const work = c.type.props.get("work");
    expect(home.type.props.get("children").type.of.type).toBe(home.type);
    expect(work.type.props.get("children").type.of.type).toBe(work.type);
    expect(keys(home)).toEqual(["children", "name", "secret"]);
    expect(keys(work)).toEqual(["children", "name"]);
    // Walking down the recursion on `work` never reveals the hidden field.
    const deep = work.type.props.get("children").type.of.type.props.get("children").type.of;
    expect(deep.type.props.has("secret")).toBe(false);
  });

  it("a union-branch use is pruned by its own path", () => {
    const union = {
      $v: 2,
      type: { kind: "union", items: [refTo("Addr"), leaf()], tags: [] },
      metadata: {},
    } as unknown as TSerializedAnnotatedType;
    const t = obj({ id: leaf(), home: addr(), u: union });
    const c = client(t, vis({ "u.secret": 0 }, new Set(["id"])));
    expect(keys(c.type.props.get("home"))).toEqual(["secret", "street"]);
    const branch = c.type.props.get("u").type.items[0];
    expect(keys(branch)).toEqual(["street"]);
  });
});

// ── fail-closed bindings ───────────────────────────────────────────────────

describe("pruneMetaByVisibility — value-help binding resolution fails closed", () => {
  const dictType = {};
  const entry = {
    metadata: {
      get: (k: string) =>
        k === "ui.valueHelp" ? { target: () => dictType, field: "code" } : undefined,
    },
  };
  const bound = (): TSerializedAnnotatedType => ({
    ...leaf(),
    metadata: { "ui.valueHelp": { field: "code" } },
  });
  const run = (type: TSerializedAnnotatedType, flat: Map<string, unknown>) => {
    const meta = { ...usersMeta(), type, relations: [] } as unknown as TMetaResponse;
    const table = {
      primaryKeys: ["id"],
      preferredId: ["id"],
      type: {},
      flatMap: flat,
    } as unknown as VisibilityTableSource;
    const v = { ...buildScopeVisibility([{}], table), table };
    return pruneMetaByVisibility(meta, v, new Map([[dictType, vis({})]])).type as any;
  };

  it("keeps a resolvable binding at an object path (control)", () => {
    const out = run(obj({ id: leaf(), color: bound() }), new Map([["color", entry]]));
    expect(out.type.props.color.metadata["ui.valueHelp"]).toBeDefined();
  });

  it("a flat-map miss strips the binding (was kept)", () => {
    const out = run(obj({ id: leaf(), color: bound() }), new Map());
    expect(out.type.props.color).toBeDefined();
    expect(out.type.props.color.metadata["ui.valueHelp"]).toBeUndefined();
  });

  it("a binding inside a union branch is ambiguous and stripped", () => {
    const union = {
      $v: 2,
      type: { kind: "union", items: [obj({ pick: bound() }), obj({ other: leaf() })], tags: [] },
      metadata: {},
    } as unknown as TSerializedAnnotatedType;
    const out = run(obj({ id: leaf(), u: union }), new Map([["u.pick", entry]]));
    expect(out.type.props.u.type.items[0].type.props.pick.metadata["ui.valueHelp"]).toBeUndefined();
  });
});

describe("applyArbacFormOverlay — depth cap fails closed", () => {
  it("strips a binding sitting beyond the walk bound (was kept)", async () => {
    const depth = 20;
    const binding = { target: () => ({}), field: "code" };
    const rt = (child?: any, bind = false): any => ({
      type: child
        ? { kind: "object", props: new Map([["n", child]]) }
        : { kind: "", designType: "string" },
      metadata: { get: (k: string) => (bind && k === "ui.valueHelp" ? binding : undefined) },
    });
    const ser = (child?: TSerializedAnnotatedType, bind = false): TSerializedAnnotatedType =>
      child
        ? obj({ n: child })
        : { ...leaf(), metadata: bind ? { "ui.valueHelp": { field: "code" } } : {} };
    let r = rt(undefined, true);
    let s = ser(undefined, true);
    for (let i = 0; i < depth; i++) {
      r = rt(r);
      s = ser(s);
    }
    const out = JSON.stringify(await applyArbacFormOverlay(s, r));
    expect(out).not.toContain("ui.valueHelp");
  });

  it("strips a wildcard prop's binding sitting beyond the walk bound", async () => {
    const binding = { target: () => ({}), field: "code" };
    const get = (bind: boolean) => (k: string) =>
      bind && k === "ui.valueHelp" ? binding : undefined;
    const leafRt = {
      type: { kind: "", designType: "string" },
      metadata: { get: get(true) },
    };
    const patternRt = (): any => ({
      type: {
        kind: "object",
        props: new Map(),
        propsPatterns: [{ pattern: /./, def: leafRt }],
      },
      metadata: { get: get(false) },
    });
    const patternSer = (): any => ({
      ...obj({}),
      type: {
        kind: "object",
        props: {},
        propsPatterns: [
          {
            pattern: { source: ".", flags: "" },
            def: { ...leaf(), metadata: { "ui.valueHelp": { field: "code" } } },
          },
        ],
        tags: [],
      },
    });
    let r: any = patternRt();
    let s: any = patternSer();
    for (let i = 0; i < 20; i++) {
      r = { type: { kind: "object", props: new Map([["n", r]]) }, metadata: { get: get(false) } };
      s = obj({ n: s });
    }
    expect(JSON.stringify(await applyArbacFormOverlay(s, r))).not.toContain("ui.valueHelp");
  });
});
