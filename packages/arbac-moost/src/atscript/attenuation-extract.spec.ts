import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import {
  extractAttenuation,
  getArbacAttenuationSpec,
  validateAttenuationTargets,
} from "./attenuation-extract";

/**
 * Build a minimal `TAtscriptAnnotatedType` whose object props carry the given
 * per-field annotation map — exactly the surface `extractAttenuation` reads
 * (`type.kind`, `type.props`, `fieldType.metadata.get`). Lets us unit-test the
 * annotation walk without compiling an `.as` fixture.
 */
function mockCredType(fields: Record<string, Record<string, unknown>>): TAtscriptAnnotatedType {
  const props = new Map<string, { metadata: { get: (k: string) => unknown } }>();
  for (const [name, anns] of Object.entries(fields)) {
    props.set(name, { metadata: { get: (k: string) => anns[k] } });
  }
  return { type: { kind: "object", props } } as unknown as TAtscriptAnnotatedType;
}

const ROLE = "arbac.attenuate.role";
const ATTR = "arbac.attenuate.attr";

describe("getArbacAttenuationSpec — annotation walk", () => {
  it("collects the single role field and the attr→userAttr mappings", () => {
    const spec = getArbacAttenuationSpec(
      mockCredType({
        assumedRoles: { [ROLE]: true },
        scopedTenant: { [ATTR]: "tenantId" },
        scopedDept: { [ATTR]: "departmentId" },
        token: {},
      }),
    );
    expect(spec.roleField).toBe("assumedRoles");
    expect(spec.attrFields).toEqual([
      { field: "scopedTenant", userAttr: "tenantId" },
      { field: "scopedDept", userAttr: "departmentId" },
    ]);
  });

  it("throws on more than one @arbac.attenuate.role field", () => {
    expect(() =>
      getArbacAttenuationSpec(mockCredType({ a: { [ROLE]: true }, b: { [ROLE]: true } })),
    ).toThrow(/multiple @arbac.attenuate.role/);
  });

  it("returns an empty spec for a model with no attenuation annotations", () => {
    const spec = getArbacAttenuationSpec(mockCredType({ token: {}, userId: {} }));
    expect(spec.roleField).toBeUndefined();
    expect(spec.attrFields).toEqual([]);
  });
});

describe("validateAttenuationTargets — boot-time cross-model check", () => {
  const credType = mockCredType({
    assumedRoles: { [ROLE]: true },
    scopedTenant: { [ATTR]: "tenantId" },
  });

  it("passes when every attr target exists in the user attr keyspace", () => {
    expect(() => validateAttenuationTargets(credType, ["tenantId", "departmentId"])).not.toThrow();
  });

  it("throws when an attr target is missing from the user attr keyspace", () => {
    const bad = mockCredType({ scopedX: { [ATTR]: "nope" } });
    expect(() => validateAttenuationTargets(bad, ["tenantId"])).toThrow(/"nope"/);
  });
});

describe("extractAttenuation — restrict-only attenuation from typed fields", () => {
  const credType = mockCredType({
    assumedRoles: { [ROLE]: true },
    scopedTenant: { [ATTR]: "tenantId" },
  });

  it("reads the assumed-role subset and attr override keyed by target name", () => {
    expect(extractAttenuation(credType, { assumedRoles: ["viewer"], scopedTenant: "t1" })).toEqual({
      roles: ["viewer"],
      attrs: { tenantId: "t1" },
    });
  });

  it("a model with no attenuation annotations → undefined (full authority)", () => {
    expect(extractAttenuation(mockCredType({ token: {} }), { token: "x" })).toBeUndefined();
  });

  it("an attenuation-capable model whose token sets nothing → undefined (full authority)", () => {
    expect(extractAttenuation(credType, { userId: "u1" })).toBeUndefined();
  });

  it("roles: [] is preserved as explicit deny-all (not dropped)", () => {
    expect(extractAttenuation(credType, { assumedRoles: [] })).toEqual({ roles: [] });
  });

  it("omitted role field with an attr set → attrs-only narrowing (roles omitted)", () => {
    expect(extractAttenuation(credType, { scopedTenant: "t1" })).toEqual({
      attrs: { tenantId: "t1" },
    });
  });

  it("fail-closed: a malformed (non-string) role value collapses to [] (deny-all)", () => {
    expect(extractAttenuation(credType, { assumedRoles: 42 })).toEqual({ roles: [] });
  });

  it("lenient: a single role string is accepted; empties/dupes dropped", () => {
    expect(extractAttenuation(credType, { assumedRoles: ["a", "", "a", "b"] })).toEqual({
      roles: ["a", "b"],
    });
  });

  it("null record → undefined", () => {
    expect(extractAttenuation(credType, null)).toBeUndefined();
  });

  it("null columns (a stateful store's unset optionals) are treated as absent, not narrowing", () => {
    // The atscript-db round-trip surfaces unset optional columns as SQL NULL —
    // a full token must NOT be clipped to a `tenantId: null` scope.
    expect(
      extractAttenuation(credType, { assumedRoles: null, scopedTenant: null }),
    ).toBeUndefined();
  });
});
