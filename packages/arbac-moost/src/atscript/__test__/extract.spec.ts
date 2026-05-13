import { beforeAll, describe, expect, it } from "vite-plus/test";

import { extractArbacAttrs, extractArbacRoles, extractArbacUserId } from "../extract";
import { prepareFixtures } from "./test-utils";

let TestUser: any;
let TestUserOverride: any;

describe("extract helpers", () => {
  beforeAll(async () => {
    await prepareFixtures();
    const fixtures = await import("./fixtures/test-user.as");
    TestUser = fixtures.TestUser;
    TestUserOverride = fixtures.TestUserOverride;
  });

  describe("extractArbacUserId", () => {
    it("falls back to @meta.id when no @arbac.userId is present", () => {
      const id = extractArbacUserId(
        { id: "user-1", username: "alice", roles: [], extraRoles: [] } as any,
        TestUser,
      );
      expect(id).toBe("user-1");
    });

    it("prefers @arbac.userId over @meta.id", () => {
      const id = extractArbacUserId(
        { id: "internal-1", externalId: "ext-42", role: "admin" } as any,
        TestUserOverride,
      );
      expect(id).toBe("ext-42");
    });

    it("coerces a numeric id to a string", () => {
      const id = extractArbacUserId({ id: 7 } as any, TestUser);
      expect(id).toBe("7");
    });

    it("throws when the resolved id field is empty", () => {
      expect(() => extractArbacUserId({ id: "" } as any, TestUser)).toThrow(
        /empty on the user record/,
      );
    });

    it("throws when the id is a non-string non-number", () => {
      expect(() => extractArbacUserId({ id: { nested: "x" } } as any, TestUser)).toThrow(
        /must be a string, number, or bigint/,
      );
    });
  });

  describe("extractArbacRoles", () => {
    it("returns a deduplicated union from every @arbac.role field", () => {
      const roles = extractArbacRoles(
        { id: "u1", roles: ["admin", "user"], extraRoles: ["user", "editor"] } as any,
        TestUser,
      );
      expect(roles).toEqual(["admin", "user", "editor"]);
    });

    it("accepts a scalar string role and an array role together", () => {
      const roles = extractArbacRoles({ role: "admin" } as any, TestUserOverride);
      expect(roles).toEqual(["admin"]);
    });

    it("skips undefined / null / empty values", () => {
      const roles = extractArbacRoles(
        { id: "u1", roles: undefined, extraRoles: null } as any,
        TestUser,
      );
      expect(roles).toEqual([]);
    });

    it("ignores non-string entries inside a role array", () => {
      const roles = extractArbacRoles(
        { id: "u1", roles: ["admin", 42 as any, ""], extraRoles: [] } as any,
        TestUser,
      );
      expect(roles).toEqual(["admin"]);
    });
  });

  describe("extractArbacAttrs", () => {
    it("returns every @arbac.attribute field keyed by prop name", () => {
      const attrs = extractArbacAttrs(
        {
          id: "u1",
          tenantId: "acme",
          department: "eng",
          secret: "should-not-leak",
        } as any,
        TestUser,
      );
      expect(attrs).toEqual({ tenantId: "acme", department: "eng" });
    });

    it("keeps undefined values so consumers can detect missing fields", () => {
      const attrs = extractArbacAttrs({ id: "u1", tenantId: "acme" } as any, TestUser);
      expect(attrs).toHaveProperty("tenantId", "acme");
      expect(attrs).toHaveProperty("department");
      expect(attrs.department).toBeUndefined();
    });

    it("returns {} when the type has no @arbac.attribute fields", () => {
      // TestUserOverride has tenantId — verify positively that
      // omission yields {} via a synthetic empty type.
      const fakeEmpty = { type: { kind: "object", props: new Map() } } as any;
      expect(extractArbacAttrs({ id: "u1" } as any, fakeEmpty)).toEqual({});
    });
  });
});
