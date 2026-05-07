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

  it("must return empty for a single empty projection", () => {
    expect(unionProjections({})).toStrictEqual({});
  });

  it("must passthrough sole include projection", () => {
    expect(unionProjections({ a: 1, b: 1 })).toStrictEqual({ a: 1, b: 1 });
  });

  it("must passthrough sole exclude projection", () => {
    expect(unionProjections({ c: 0 })).toStrictEqual({ c: 0 });
  });

  it("must return empty when any projection is empty (universal grant wins)", () => {
    expect(unionProjections({ name: 1 }, {})).toStrictEqual({});
  });

  it("must union include projections", () => {
    expect(unionProjections({ name: 1 }, { email: 1 })).toStrictEqual({
      email: 1,
      name: 1,
    });
  });

  it("must deduplicate include keys", () => {
    expect(unionProjections({ name: 1, email: 1 }, { email: 1, age: 1 })).toStrictEqual({
      age: 1,
      email: 1,
      name: 1,
    });
  });

  it("must return empty for two excludes with no shared exclusions", () => {
    // {c:0} grants universe \ {c}; {d:0} grants universe \ {d}; together = universe
    expect(unionProjections({ c: 0 }, { d: 0 })).toStrictEqual({});
  });

  it("must intersect identical exclude keys", () => {
    expect(unionProjections({ c: 0 }, { c: 0 })).toStrictEqual({ c: 0 });
  });

  it("must intersect exclude projections (only commonly excluded fields remain)", () => {
    expect(unionProjections({ c: 0, d: 0 }, { c: 0 })).toStrictEqual({ c: 0 });
  });

  it("must produce exclude-mode result for mixed include + exclude (additive)", () => {
    // {a:1, b:1} grants {a, b}; {c:0} grants universe \ {c} — union = universe \ {c}
    expect(unionProjections({ a: 1, b: 1 }, { c: 0 })).toStrictEqual({ c: 0 });
  });

  it("must collapse to universe when an include grants the only excluded field", () => {
    // {a:1, b:1} grants {a, b}; {b:0} grants universe \ {b}; union = universe
    expect(unionProjections({ a: 1, b: 1 }, { b: 0 })).toStrictEqual({});
  });

  it("must collapse to universe when include cancels exclude", () => {
    expect(unionProjections({ e: 0 }, { e: 1 })).toStrictEqual({});
  });

  it("must collapse to universe when includes cover all excluded fields", () => {
    expect(unionProjections({ a: 1, b: 1 }, { a: 0, b: 0 })).toStrictEqual({});
  });

  it("must union three include projections", () => {
    expect(unionProjections({ name: 1 }, { email: 1 }, { age: 1, name: 1 })).toStrictEqual({
      age: 1,
      email: 1,
      name: 1,
    });
  });

  it("must intersect three exclude projections", () => {
    expect(
      unionProjections(
        { password: 0, secret: 0 },
        { password: 0, token: 0 },
        { password: 0, ssn: 0 },
      ),
    ).toStrictEqual({ password: 0 });
  });

  it("must throw when a single projection mixes 1 and 0 keys", () => {
    expect(() => unionProjections({ a: 1, b: 0 })).toThrow(
      "projection mixes 1 and 0 within itself",
    );
  });

  it("must throw for invalid projection value", () => {
    expect(() =>
      unionProjections({ a: "x" } as unknown as Parameters<typeof unionProjections>[0]),
    ).toThrow("invalid projection value");
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

  describe("nested-path interaction", () => {
    it("must keep nested desired key when its parent is allowed by access control", () => {
      // desired wants only user.email; access control allows the whole `user` subtree
      expect(restrictProjection({ "user.email": 1 }, { user: 1 })).toStrictEqual({
        "user.email": 1,
      });
    });

    it("must drop nested desired key when its parent is excluded by access control", () => {
      // access control excludes the whole `user` subtree; desired's user.email is therefore disallowed
      expect(restrictProjection({ "user.email": 1, name: 1 }, { user: 0 })).toStrictEqual({
        name: 1,
      });
    });

    it("must keep parent desired key when access control includes a nested child", () => {
      // desired wants `user`; access control allows it via the nested `user.email` entry
      // (isFieldAllowed("user", {"user.email": 1}) is true). The result keeps the desired key
      // as-is — narrowing further is the caller's responsibility.
      expect(restrictProjection({ user: 1 }, { "user.email": 1 })).toStrictEqual({
        user: 1,
      });
    });

    it("must keep nested key on both sides when both narrow to the same parent", () => {
      expect(
        restrictProjection({ "user.email": 1, "user.name": 1 }, { "user.email": 1 }),
      ).toStrictEqual({ "user.email": 1 });
    });
  });
});
