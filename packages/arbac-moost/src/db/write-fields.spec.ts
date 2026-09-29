import { describe, expect, it } from "vite-plus/test";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { applyAllowedFieldsAndSet } from "./write-fields";

const merge = (paths: string[]) => (p: string) => paths.includes(p);

describe("applyAllowedFieldsAndSet — path-aware whitelist", () => {
  it("a top-level entry keeps the whole subtree", () => {
    const scopes: ArbacDbScope[] = [{ allowedFields: ["profile"] }];
    expect(applyAllowedFieldsAndSet({ profile: { a: 1, b: 2 }, x: 1 }, scopes)).toEqual({
      profile: { a: 1, b: 2 },
    });
  });

  it("a dotted entry keeps only that branch of a nested object", () => {
    const scopes: ArbacDbScope[] = [{ allowedFields: ["profile.name", "a.b.c"] }];
    expect(
      applyAllowedFieldsAndSet(
        { profile: { name: "n", tenant: "t" }, a: { b: { c: 1, d: 2 }, e: 3 } },
        scopes,
      ),
    ).toEqual({ profile: { name: "n" }, a: { b: { c: 1 } } });
  });

  it("a non-object (or emptied) value under a partially whitelisted key is dropped", () => {
    const scopes: ArbacDbScope[] = [{ allowedFields: ["profile.name"] }];
    expect(applyAllowedFieldsAndSet({ profile: null }, scopes)).toEqual({});
    expect(applyAllowedFieldsAndSet({ profile: "x" }, scopes)).toEqual({});
    expect(applyAllowedFieldsAndSet({ profile: { tenant: "t" } }, scopes)).toEqual({});
  });

  it("dotted payload keys pass when the path (or an ancestor) is whitelisted", () => {
    const scopes: ArbacDbScope[] = [{ allowedFields: ["profile.name", "meta"] }];
    expect(
      applyAllowedFieldsAndSet({ "profile.name": 1, "profile.tenant": 2, "meta.x": 3 }, scopes),
    ).toEqual({ "profile.name": 1, "meta.x": 3 });
  });

  it("preserved fields ($cas, version, identifiers) survive a whitelist", () => {
    const scopes: ArbacDbScope[] = [{ allowedFields: ["title"] }];
    expect(
      applyAllowedFieldsAndSet(
        { id: 1, version: 3, $cas: { version: 3 }, title: "t", x: 1 },
        scopes,
        ["id", "version", "$cas"],
      ),
    ).toEqual({ id: 1, version: 3, $cas: { version: 3 }, title: "t" });
  });

  it("patch: a partially whitelisted replace block is dropped, a merge block pruned", () => {
    const scopes: ArbacDbScope[] = [{ allowedFields: ["profile.name", "settings.theme"] }];
    const data = { profile: { name: "n", tenant: "t" }, settings: { theme: "d", locked: "y" } };
    expect(applyAllowedFieldsAndSet(data, scopes, [], merge(["settings"]))).toEqual({
      settings: { theme: "d" },
    });
  });
});

describe("applyAllowedFieldsAndSet — dotted `set`", () => {
  const scopes: ArbacDbScope[] = [{ set: { "profile.tenant": "a", "settings.locked": "no" } }];

  it("full rows: sets the nested path, merging into the payload's object", () => {
    expect(applyAllowedFieldsAndSet({ profile: { name: "n", tenant: "b" } }, scopes)).toEqual({
      profile: { name: "n", tenant: "a" },
      settings: { locked: "no" },
    });
  });

  it("does not mutate the input and replaces a literal dotted key", () => {
    const data = { profile: { name: "n" }, "profile.tenant": "b" };
    const out = applyAllowedFieldsAndSet(data, scopes);
    expect(out).toEqual({ profile: { name: "n", tenant: "a" }, settings: { locked: "no" } });
    expect(data).toEqual({ profile: { name: "n" }, "profile.tenant": "b" });
  });

  it("patch: never adds a replace block the patch lacks; a merge block is added", () => {
    expect(applyAllowedFieldsAndSet({ title: "t" }, scopes, [], merge(["settings"]))).toEqual({
      title: "t",
      settings: { locked: "no" },
    });
    expect(
      applyAllowedFieldsAndSet({ profile: { name: "n" } }, scopes, [], merge(["settings"])),
    ).toEqual({ profile: { name: "n", tenant: "a" }, settings: { locked: "no" } });
  });
});
