import type { TMetaResponse } from "@atscript/db";
import type { TSerializedAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import {
  collectWithGrantNames,
  isMetaFieldVisible,
  pruneMetaByVisibility,
  unionScopeProjection,
} from "./meta-projection";
import type { MetaVisibility } from "./meta-projection";

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

  it("paths under a with-granted relation pass through to the sub-scope's enforcement", () => {
    const v = vis({ username: 1 }, NONE, new Set(["department"]));
    expect(isMetaFieldVisible("department", v)).toBe(true);
    expect(isMetaFieldVisible("department.name", v)).toBe(true);
    expect(isMetaFieldVisible("auditEvents.kind", v)).toBe(false);
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

  it("ancestor grants cover nested paths (credit.credentials covers .user)", () => {
    const out = pruneMetaByVisibility(usersMeta(), visW(new Set(["password"])));
    // "password.history" sits under the "password" grant.
    expect(out.fields["password.history"]?.writeOnly).toBe(true);
  });
});
