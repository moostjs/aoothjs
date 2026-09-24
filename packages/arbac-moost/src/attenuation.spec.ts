import { describe, expect, it } from "vite-plus/test";

import { conjoinArbacDbScopes } from "./attenuation";
import type { ArbacDbScope } from "./db/as-arbac-db-controller";

/** Schema lookup for a nested object `a: { b, c }`. */
const childrenOf = (p: string) => (p === "a" ? ["a.b", "a.c"] : []);

describe("conjoinArbacDbScopes — composite restrict-only conjunction", () => {
  it("filter: $and of the two unions ({} side is the identity)", () => {
    // user restricts by tenant; cred adds an owner restriction → both must hold.
    const out = conjoinArbacDbScopes([{ filter: { tenant: "a" } }], [{ filter: { owner: "u" } }]);
    expect(out).toHaveLength(1);
    expect(out[0].filter).toStrictEqual({ $and: [{ tenant: "a" }, { owner: "u" }] });
  });

  it("filter: a cred pass with no filter leaves the user filter intact (identity)", () => {
    const out = conjoinArbacDbScopes([{ filter: { tenant: "a" } }], [{}]);
    expect(out[0].filter).toStrictEqual({ tenant: "a" });
  });

  it("ATTR-WIDEN regression: a wider cred filter is clipped, never widens", () => {
    // The user can see only w1; a credential whose attrs tried to widen to
    // [w1,w2] still produces a cred filter for [w1,w2], but the $and with the
    // user's {w1} means only w1 survives — the credential can never see w2.
    const userScopes: ArbacDbScope[] = [{ filter: { wiki: { $in: ["w1"] } } }];
    const credScopes: ArbacDbScope[] = [{ filter: { wiki: { $in: ["w1", "w2"] } } }];
    const out = conjoinArbacDbScopes(userScopes, credScopes);
    expect(out[0].filter).toStrictEqual({
      $and: [{ wiki: { $in: ["w1"] } }, { wiki: { $in: ["w1", "w2"] } }],
    });
    // The $and is satisfiable only by rows where wiki ∈ {w1} ∩ {w1,w2} = {w1}.
  });

  it("projection: field-set intersection (cred may see FEWER fields)", () => {
    const out = conjoinArbacDbScopes([{ projection: { a: 1, b: 1 } }], [{ projection: { a: 1 } }]);
    expect(out[0].projection).toStrictEqual({ a: 1 });
  });

  it("projection: a parent narrows to the other side's nested whitelist (never widens)", () => {
    const out = conjoinArbacDbScopes([{ projection: { a: 1 } }], [{ projection: { "a.b": 1 } }]);
    expect(out[0].projection).toStrictEqual({ "a.b": 1 });
    const rev = conjoinArbacDbScopes([{ projection: { "a.b": 1 } }], [{ projection: { a: 1 } }]);
    expect(rev[0].projection).toStrictEqual({ "a.b": 1 });
  });

  it("projection: a nested exclusion under an included parent — exact with a schema, fail-closed without", () => {
    const user: ArbacDbScope[] = [{ projection: { a: 1, t: 1 } }];
    const cred: ArbacDbScope[] = [{ projection: { "a.c": 0 } }];
    expect(conjoinArbacDbScopes(user, cred, childrenOf)[0].projection).toStrictEqual({
      "a.b": 1,
      t: 1,
    });
    expect(conjoinArbacDbScopes(user, cred)[0].projection).toStrictEqual({ t: 1 });
  });

  it("projection: no common field → user projection + match-nothing filter (never {})", () => {
    const out = conjoinArbacDbScopes(
      [{ projection: { a: 1 }, filter: { tenant: "x" } }],
      [{ projection: { a: 0 } }],
    );
    expect(out[0].projection).toStrictEqual({ a: 1 });
    expect(out[0].filter).toStrictEqual({ $and: [{ tenant: "x" }, { $or: [] }] });
  });

  it("controls: deny-wins intersection", () => {
    // user allows $with (silent), cred denies it → denied.
    const out = conjoinArbacDbScopes([{}], [{ controls: { $with: false } }]);
    expect(out[0].controls).toStrictEqual({ $with: false });
  });

  it("controls: whitelist ∩ whitelist", () => {
    const out = conjoinArbacDbScopes(
      [{ controls: { $with: ["comments", "owner"] } }],
      [{ controls: { $with: ["comments", "tags"] } }],
    );
    expect(out[0].controls).toStrictEqual({ $with: ["comments"] });
  });

  it("allowedFields: write-whitelist intersection (cred may write FEWER fields)", () => {
    const out = conjoinArbacDbScopes(
      [{ allowedFields: ["title", "body"] }],
      [{ allowedFields: ["title"] }],
    );
    expect(out[0].allowedFields).toStrictEqual(["title"]);
  });

  it("set: forced overlays combine; the user's value wins a key conflict", () => {
    const out = conjoinArbacDbScopes(
      [{ set: { tenant: "a", flagged: true } }],
      [{ set: { tenant: "EVIL", extra: 1 } }],
    );
    // user's tenant wins; cred can only ADD (extra), never override the owner.
    expect(out[0].set).toStrictEqual({ tenant: "a", flagged: true, extra: 1 });
  });

  it("with: recurses the conjunction per joined relation", () => {
    const out = conjoinArbacDbScopes(
      [{ with: { comments: { filter: { hidden: false } } } }],
      [{ with: { comments: { filter: { authorId: "u" } } } }],
    );
    expect(out[0].with?.comments?.filter).toStrictEqual({
      $and: [{ hidden: false }, { authorId: "u" }],
    });
  });

  it("with: a relation only the cred restricts narrows it (user silent = unrestricted)", () => {
    const out = conjoinArbacDbScopes([{}], [{ with: { comments: { filter: { authorId: "u" } } } }]);
    expect(out[0].with?.comments?.filter).toStrictEqual({ authorId: "u" });
  });

  it("two fully-unrestricted passes → one empty composite scope", () => {
    expect(conjoinArbacDbScopes([{}], [{}])).toStrictEqual([{}]);
  });
});
