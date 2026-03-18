import { describe, expect, it } from "vite-plus/test";

import {
  getProjectionMode,
  isFieldAllowed,
  restrictProjection,
  unionProjections,
} from "./projection";

describe("getProjectionMode", () => {
  it("must return empty for empty projection", () => {
    expect(getProjectionMode({})).toBe("empty");
  });

  it("must return include for all-1 projection", () => {
    expect(getProjectionMode({ name: 1, email: 1 })).toBe("include");
  });

  it("must return exclude for all-0 projection", () => {
    expect(getProjectionMode({ password: 0, secret: 0 })).toBe("exclude");
  });

  it("must throw for mixed projection", () => {
    expect(() => getProjectionMode({ name: 1, password: 0 })).toThrow("cannot mix");
  });
});

describe("isFieldAllowed", () => {
  it("must allow all fields for empty projection", () => {
    expect(isFieldAllowed("anything", {})).toBe(true);
  });

  describe("inclusion mode", () => {
    it("must allow listed fields", () => {
      expect(isFieldAllowed("name", { name: 1, email: 1 })).toBe(true);
    });

    it("must deny unlisted fields", () => {
      expect(isFieldAllowed("password", { name: 1, email: 1 })).toBe(false);
    });

    it("must allow child of included parent", () => {
      expect(isFieldAllowed("address.city", { address: 1 })).toBe(true);
    });

    it("must allow parent that has included children", () => {
      expect(isFieldAllowed("address", { "address.city": 1 })).toBe(true);
    });
  });

  describe("exclusion mode", () => {
    it("must deny excluded field", () => {
      expect(isFieldAllowed("password", { password: 0 })).toBe(false);
    });

    it("must allow non-excluded field", () => {
      expect(isFieldAllowed("name", { password: 0 })).toBe(true);
    });

    it("must deny child of excluded parent", () => {
      expect(isFieldAllowed("secret.key", { secret: 0 })).toBe(false);
    });

    it("must allow parent when only child is excluded", () => {
      expect(isFieldAllowed("data", { "data.secret": 0 })).toBe(true);
    });
  });
});

describe("unionProjections", () => {
  it("must return empty for zero arguments", () => {
    expect(unionProjections()).toStrictEqual({});
  });

  it("must return empty when any projection is empty", () => {
    expect(unionProjections({ name: 1 }, {})).toStrictEqual({});
  });

  it("must union include projections", () => {
    expect(unionProjections({ name: 1 }, { email: 1 })).toStrictEqual({
      name: 1,
      email: 1,
    });
  });

  it("must deduplicate include keys", () => {
    expect(unionProjections({ name: 1, email: 1 }, { email: 1, age: 1 })).toStrictEqual({
      name: 1,
      email: 1,
      age: 1,
    });
  });

  it("must intersect exclude projections", () => {
    expect(unionProjections({ password: 0, secret: 0 }, { password: 0, token: 0 })).toStrictEqual({
      password: 0,
    });
  });

  it("must return empty for exclude with no common keys", () => {
    expect(unionProjections({ password: 0 }, { secret: 0 })).toStrictEqual({});
  });

  it("must return empty for mixed include and exclude", () => {
    expect(unionProjections({ name: 1 }, { password: 0 })).toStrictEqual({});
  });
});

describe("restrictProjection", () => {
  it("must return desired when access control is empty", () => {
    expect(restrictProjection({ name: 1 }, {})).toStrictEqual({ name: 1 });
  });

  it("must return access control when desired is empty", () => {
    expect(restrictProjection({}, { name: 1 })).toStrictEqual({ name: 1 });
  });

  it("must intersect two include projections", () => {
    expect(
      restrictProjection({ name: 1, email: 1, salary: 1 }, { name: 1, email: 1 }),
    ).toStrictEqual({ name: 1, email: 1 });
  });

  it("must union two exclude projections", () => {
    expect(restrictProjection({ password: 0 }, { secret: 0 })).toStrictEqual({
      password: 0,
      secret: 0,
    });
  });

  it("must filter include by exclude", () => {
    expect(restrictProjection({ name: 1, password: 1, email: 1 }, { password: 0 })).toStrictEqual({
      name: 1,
      email: 1,
    });
  });

  it("must handle exclude desired with include access control", () => {
    expect(restrictProjection({ secret: 0 }, { name: 1, email: 1, secret: 1 })).toStrictEqual({
      name: 1,
      email: 1,
    });
  });
});
