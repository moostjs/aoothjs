import { HttpError } from "@moostjs/event-http";
import { describe, expect, it } from "vite-plus/test";

import { effectiveScope } from "@aooth/arbac";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { assertNestedWritesAllowed } from "./write-policy";

const mergedScopeCheck = (scopes: ArbacDbScope[]) => effectiveScope(scopes).check;
const mergedScopeFilter = (scopes: ArbacDbScope[]) => effectiveScope(scopes).filter;

const NAV = new Set(["owner", "notes"]);

describe("assertNestedWritesAllowed", () => {
  it("denies a nav key (incl. dotted) unless a scope lists it", () => {
    expect(() => assertNestedWritesAllowed({ owner: {} }, [{}], NAV)).toThrow(HttpError);
    expect(() => assertNestedWritesAllowed({ "owner.name": "x" }, [{}], NAV)).toThrow(
      'Nested writes through "owner" are not allowed',
    );
    expect(() =>
      assertNestedWritesAllowed(
        { owner: {} },
        [{ nestedWrites: ["notes"] }, { nestedWrites: ["owner"] }],
        NAV,
      ),
    ).not.toThrow();
  });

  it("checks every row of a batch; plain fields pass", () => {
    expect(() => assertNestedWritesAllowed([{ title: "t" }, { notes: [] }], [{}], NAV)).toThrow(
      /"notes"/,
    );
    expect(() => assertNestedWritesAllowed([{ title: "t" }], [{}], NAV)).not.toThrow();
  });
});

describe("effective filter / check of write scopes", () => {
  it("check defaults to filter, `{}` opts out, an unrestricted scope wins the union", () => {
    expect(mergedScopeCheck([{ filter: { t: "a" } }])).toEqual({ t: "a" });
    expect(mergedScopeCheck([{ filter: { t: "a" }, check: {} }])).toBeUndefined();
    expect(mergedScopeCheck([{ filter: { t: "a" } }, { check: { s: 1 } }])).toEqual({
      $or: [{ t: "a" }, { s: 1 }],
    });
    expect(mergedScopeFilter([{ filter: { t: "a" } }, {}])).toBeUndefined();
  });
});
