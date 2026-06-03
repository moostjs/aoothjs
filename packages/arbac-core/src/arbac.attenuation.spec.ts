import { describe, expect, it } from "vite-plus/test";

import { Arbac } from "./arbac";

// Attrs feed scope predicates; the scope shape is a simple field-set so the
// two passes' scope outputs are easy to assert. The conjunction itself lives
// in @aooth/arbac / @aooth/arbac-moost (the engine is scope-agnostic); here we
// only assert the engine's OUTCOME-intersection (allow-AND, role-subset) and
// that the credential pass's attr merge stays LOCAL.
type Attrs = { docs: string[] };
type Scope = { docs: string[] };

function makeArbac(): Arbac<Attrs, Scope> {
  const arbac = new Arbac<Attrs, Scope>();
  arbac.registerRole({ id: "editor", rules: [{ action: "post", resource: "doc" }] });
  arbac.registerRole({ id: "admin", rules: [{ action: "delete", resource: "doc" }] });
  arbac.registerRole({
    id: "suspended",
    rules: [{ action: "post", effect: "deny", resource: "doc" }],
  });
  arbac.registerRole({
    id: "scoped-reader",
    rules: [{ action: "read", resource: "doc", scope: (a) => ({ docs: a.docs }) }],
  });
  return arbac;
}

const attrs: Attrs = { docs: ["d1", "d2"] };

describe("arbac attenuation — restrict-only outcome intersection", () => {
  it("absent attenuate → byte-identical to a single evaluation (no credScopes key)", async () => {
    const arbac = makeArbac();
    expect(
      await arbac.evaluate(
        { resource: "doc", action: "post" },
        { id: "u", roles: ["editor"], attrs },
      ),
    ).toStrictEqual({ allowed: true, scopes: [{}] });
  });

  it("DENY-DROP regression: dropping a denying role can NOT escalate denied→allowed", async () => {
    const arbac = makeArbac();
    const user = { id: "u", roles: ["editor", "suspended"], attrs };
    // user holds editor.allow(post) + suspended.deny(post) → denied (deny-wins).
    expect(await arbac.evaluate({ resource: "doc", action: "post" }, user)).toStrictEqual({
      allowed: false,
    });
    // a token claiming ONLY editor — a strict SUBSET — stays denied, because the
    // user pass still denies. Intersecting the role SET would have wrongly allowed.
    expect(
      await arbac.evaluate(
        { resource: "doc", action: "post" },
        { ...user, attenuate: { roles: ["editor"] } },
      ),
    ).toStrictEqual({ allowed: false });
  });

  it("subset roles narrow the allow set", async () => {
    const arbac = makeArbac();
    const user = { id: "u", roles: ["editor", "admin"], attrs };
    // delete is admin-only → attenuating to [editor] drops it.
    expect(
      await arbac.evaluate(
        { resource: "doc", action: "delete" },
        { ...user, attenuate: { roles: ["editor"] } },
      ),
    ).toStrictEqual({ allowed: false });
    // post is still allowed (editor retained); both passes agree.
    expect(
      await arbac.evaluate(
        { resource: "doc", action: "post" },
        { ...user, attenuate: { roles: ["editor"] } },
      ),
    ).toStrictEqual({ allowed: true, scopes: [{}], credScopes: [{}] });
  });

  it("a claimed role the user lacks is a no-op (fail-closed, never widens)", async () => {
    const arbac = makeArbac();
    expect(
      await arbac.evaluate(
        { resource: "doc", action: "post" },
        { id: "u", roles: ["editor"], attrs, attenuate: { roles: ["admin"] } },
      ),
    ).toStrictEqual({ allowed: false });
  });

  it("roles: [] denies everything (deny-all, fail-closed) — distinct from omitted", async () => {
    const arbac = makeArbac();
    expect(
      await arbac.evaluate(
        { resource: "doc", action: "post" },
        { id: "u", roles: ["editor", "admin"], attrs, attenuate: { roles: [] } },
      ),
    ).toStrictEqual({ allowed: false });
  });

  it("omitted roles key keeps all roles (attrs-only narrowing) + surfaces both scope passes", async () => {
    const arbac = makeArbac();
    const res = await arbac.evaluate(
      { resource: "doc", action: "read" },
      {
        id: "u",
        roles: ["scoped-reader"],
        attrs: { docs: ["d1", "d2"] },
        attenuate: { attrs: { docs: ["d1"] } },
      },
    );
    expect(res.allowed).toBe(true);
    expect(res.scopes).toStrictEqual([{ docs: ["d1", "d2"] }]); // ceiling
    expect(res.credScopes).toStrictEqual([{ docs: ["d1"] }]); // narrowed
  });

  it("the credential attr merge is LOCAL — it never widens the ceiling pass", async () => {
    const arbac = makeArbac();
    // attenuation attrs are WIDER than the user's. The ceiling pass must still
    // see only the user's attrs; the clip to the ceiling is the scope layer's
    // conjunction job — here we prove the merge doesn't leak upward.
    const res = await arbac.evaluate(
      { resource: "doc", action: "read" },
      {
        id: "u",
        roles: ["scoped-reader"],
        attrs: { docs: ["d1"] },
        attenuate: { attrs: { docs: ["d1", "d2"] } },
      },
    );
    expect(res.scopes).toStrictEqual([{ docs: ["d1"] }]); // ceiling = user attrs only
    expect(res.credScopes).toStrictEqual([{ docs: ["d1", "d2"] }]); // cred pass merged
  });
});
