import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { getAoothUserHandleSpec } from "./handle-spec";

/**
 * Build a minimal `TAtscriptAnnotatedType` whose object props carry the given
 * per-field annotation map — exactly the surface `getAoothUserHandleSpec` reads
 * (`type.kind`, `type.props`, `fieldType.metadata.get`). Lets us unit-test the
 * annotation walk without compiling an `.as` fixture. Mirrors the helper in
 * `attenuation-extract.spec.ts`.
 */
function mockUserType(fields: Record<string, Record<string, unknown>>): TAtscriptAnnotatedType {
  const props = new Map<string, { metadata: { get: (k: string) => unknown } }>();
  for (const [name, anns] of Object.entries(fields)) {
    props.set(name, { metadata: { get: (k: string) => anns[k] } });
  }
  return { type: { kind: "object", props } } as unknown as TAtscriptAnnotatedType;
}

const EMAIL = "aooth.user.email";
const PHONE = "aooth.user.phone";
const UNIQUE = "db.index.unique";

describe("getAoothUserHandleSpec — @aooth.user.* handle resolution", () => {
  it("discovers the email + phone handle fields (each unique-indexed)", () => {
    const spec = getAoothUserHandleSpec(
      mockUserType({
        username: { [UNIQUE]: ["username_idx"] },
        email: { [EMAIL]: true, [UNIQUE]: ["email_idx"] },
        phone: { [PHONE]: true, [UNIQUE]: ["phone_idx"] },
        displayName: {},
      }),
    );
    expect(spec.emailField).toBe("email");
    expect(spec.phoneField).toBe("phone");
    expect(spec.handleFields).toEqual(["email", "phone"]);
    expect(spec.warnings).toEqual([]);
  });

  it("resolves name-agnostically — the field need not be named 'email'", () => {
    const spec = getAoothUserHandleSpec(
      mockUserType({ contactEmail: { [EMAIL]: true, [UNIQUE]: [true] } }),
    );
    expect(spec.emailField).toBe("contactEmail");
  });

  it("returns all-undefined for a model with no @aooth.user.* fields (graceful degradation)", () => {
    const spec = getAoothUserHandleSpec(
      mockUserType({ username: { [UNIQUE]: [true] }, token: {} }),
    );
    expect(spec.emailField).toBeUndefined();
    expect(spec.phoneField).toBeUndefined();
    expect(spec.warnings).toEqual([]);
  });

  it("warn-and-disable: an email handle without @db.index.unique is dropped with a warning", () => {
    const spec = getAoothUserHandleSpec(mockUserType({ email: { [EMAIL]: true } }));
    expect(spec.emailField).toBeUndefined();
    expect(spec.warnings).toHaveLength(1);
    expect(spec.warnings[0]).toMatch(/@aooth\.user\.email/);
    expect(spec.warnings[0]).toMatch(/no @db\.index\.unique/);
  });

  it("disables only the offending handle (email unique, phone non-unique)", () => {
    const spec = getAoothUserHandleSpec(
      mockUserType({
        email: { [EMAIL]: true, [UNIQUE]: ["email_idx"] },
        phone: { [PHONE]: true },
      }),
    );
    expect(spec.emailField).toBe("email");
    expect(spec.phoneField).toBeUndefined();
    expect(spec.handleFields).toEqual(["email"]);
    expect(spec.warnings).toHaveLength(1);
    expect(spec.warnings[0]).toMatch(/phone/);
  });

  it("treats an empty @db.index.unique array as no unique index (disabled)", () => {
    const spec = getAoothUserHandleSpec(mockUserType({ email: { [EMAIL]: true, [UNIQUE]: [] } }));
    expect(spec.emailField).toBeUndefined();
    expect(spec.warnings).toHaveLength(1);
  });

  it("throws on more than one @aooth.user.email field (ambiguity)", () => {
    expect(() =>
      getAoothUserHandleSpec(
        mockUserType({
          email: { [EMAIL]: true, [UNIQUE]: [true] },
          altEmail: { [EMAIL]: true, [UNIQUE]: [true] },
        }),
      ),
    ).toThrow(/multiple @aooth\.user\.email/);
  });

  it("throws on more than one @aooth.user.phone field (ambiguity)", () => {
    expect(() =>
      getAoothUserHandleSpec(
        mockUserType({
          p1: { [PHONE]: true, [UNIQUE]: [true] },
          p2: { [PHONE]: true, [UNIQUE]: [true] },
        }),
      ),
    ).toThrow(/multiple @aooth\.user\.phone/);
  });

  it("caches the spec per type (same reference returned)", () => {
    const t = mockUserType({ email: { [EMAIL]: true, [UNIQUE]: [true] } });
    expect(getAoothUserHandleSpec(t)).toBe(getAoothUserHandleSpec(t));
  });

  it("handles a non-object type gracefully", () => {
    const spec = getAoothUserHandleSpec({
      type: { kind: "string" },
    } as unknown as TAtscriptAnnotatedType);
    expect(spec.emailField).toBeUndefined();
    expect(spec.phoneField).toBeUndefined();
    expect(spec.warnings).toEqual([]);
  });
});
