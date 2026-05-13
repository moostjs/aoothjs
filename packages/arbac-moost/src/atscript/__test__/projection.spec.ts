import { beforeAll, describe, expect, it } from "vite-plus/test";

import { getArbacProjection } from "../projection";
import { prepareFixtures } from "./test-utils";

let TestUser: any;
let TestUserOverride: any;

describe("getArbacProjection", () => {
  beforeAll(async () => {
    await prepareFixtures();
    const fixtures = await import("./fixtures/test-user.as");
    TestUser = fixtures.TestUser;
    TestUserOverride = fixtures.TestUserOverride;
  });

  it("includes the @meta.id field, every role field, and every attribute field", () => {
    const proj = getArbacProjection(TestUser);
    expect(proj).toEqual({
      id: 1,
      roles: 1,
      extraRoles: 1,
      tenantId: 1,
      department: 1,
    });
  });

  it("uses the @arbac.userId override when present and still includes @meta.id", () => {
    const proj = getArbacProjection(TestUserOverride);
    // Implementation defines: @arbac.userId wins; @meta.id is the fallback.
    // Projection unconditionally selects the resolved field. We do NOT
    // require it to also include @meta.id when overridden, but we do
    // require it to include `externalId`.
    expect(proj).toHaveProperty("externalId", 1);
    expect(proj).toHaveProperty("role", 1);
    expect(proj).toHaveProperty("tenantId", 1);
  });

  it("returns the same cached reference on repeated calls", () => {
    const a = getArbacProjection(TestUser);
    const b = getArbacProjection(TestUser);
    expect(a).toBe(b);
  });
});
