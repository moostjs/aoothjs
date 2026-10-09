import { describe, expect, it, vi } from "vite-plus/test";

import { Arbac } from "./arbac";
import type { TArbacEvalResult, TArbacRole, TArbacRule } from "./types";
import { arbacPatternToRegex } from "./utils";

type Attrs = { tenant: string };
type Scope = { tag: string };

/** The pre-memo evaluation (per-rule regex test, per-scope attrs await) — the reference. */
async function reference(
  roles: Array<TArbacRole<Attrs, Scope>>,
  res: { resource: string; action: string },
  roleIds: string[],
  attrs: Attrs,
  id: string,
): Promise<TArbacEvalResult<Scope>> {
  const byId = new Map(roles.map((r) => [r.id, r]));
  const compiled = roleIds
    .map((rid) => byId.get(rid))
    .filter((r): r is TArbacRole<Attrs, Scope> => !!r)
    .map((role) => {
      const allow: TArbacRule<Attrs, Scope>[] = [];
      const deny: TArbacRule<Attrs, Scope>[] = [];
      for (const rule of role.rules) {
        if (!arbacPatternToRegex(rule.resource).test(res.resource)) continue;
        (rule.effect === "deny" ? deny : allow).push(rule);
      }
      return { allow, deny };
    });
  if (compiled.length === 0) return { allowed: false };
  for (const role of compiled) {
    for (const rule of role.deny) {
      if (arbacPatternToRegex(rule.action).test(res.action)) return { allowed: false };
    }
  }
  const scopes: Scope[] = [];
  let allowed = false;
  for (const role of compiled) {
    for (const rule of role.allow) {
      if (arbacPatternToRegex(rule.action).test(res.action)) {
        allowed = true;
        scopes.push(rule.scope ? rule.scope(attrs, id) : ({} as Scope));
      }
    }
  }
  return allowed ? { allowed, scopes } : { allowed };
}

/** Deterministic PRNG (mulberry32) so a failure reproduces. */
function rng(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const RESOURCES = ["tasks", "users", "auth.login", "auth.mfa", "docs.v1.files"];
const RESOURCE_PATTERNS = ["tasks", "users", "auth.*", "auth.**", "docs.*.files", "*", "**"];
const ACTIONS = ["query", "insert", "update", "remove", "markDone", "a.b", "a.c.d"];
const ACTION_PATTERNS = ["query", "update", "*", "**", "a.*", "a.**", "mark*", "insert"];

function randomRoles(next: () => number): Array<TArbacRole<Attrs, Scope>> {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)];
  return Array.from({ length: 4 }, (_, i) => ({
    id: `r${i}`,
    rules: Array.from({ length: 1 + Math.floor(next() * 6) }, (_, j) => {
      const resource = pick(RESOURCE_PATTERNS);
      const action = pick(ACTION_PATTERNS);
      if (next() < 0.15) return { resource, action, effect: "deny" as const };
      const tag = `r${i}.${j}`;
      return next() < 0.5
        ? { resource, action }
        : {
            resource,
            action,
            scope: (a: Attrs, uid: string) => ({ tag: `${tag}:${a.tenant}:${uid}` }),
          };
    }),
  }));
}

describe("arbac rule-match memo", () => {
  it("evaluates exactly like the unmemoized reference (randomized policies, repeated calls)", async () => {
    for (let seed = 1; seed <= 40; seed++) {
      const next = rng(seed);
      const roles = randomRoles(next);
      const arbac = new Arbac<Attrs, Scope>();
      for (const role of roles) arbac.registerRole(role);
      const attrs = { tenant: `t${seed}` };
      for (let k = 0; k < 60; k++) {
        const roleIds = roles.map((r) => r.id).filter(() => next() < 0.6);
        if (next() < 0.2) roleIds.push("ghost");
        const res = {
          resource: RESOURCES[Math.floor(next() * RESOURCES.length)],
          action: ACTIONS[Math.floor(next() * ACTIONS.length)],
        };
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        const got = await arbac.evaluate(res, { id: "u1", roles: roleIds, attrs });
        warn.mockRestore();
        expect(got).toStrictEqual(await reference(roles, res, roleIds, attrs, "u1"));
      }
    }
  });

  it("deny wins over an earlier role's allow", async () => {
    const arbac = new Arbac<Attrs, Scope>()
      .registerRole({ id: "a", rules: [{ resource: "t", action: "*" }] })
      .registerRole({ id: "d", rules: [{ resource: "t", action: "remove", effect: "deny" }] });
    const user = { id: "u", roles: ["a", "d"], attrs: { tenant: "x" } };
    expect(await arbac.evaluate({ resource: "t", action: "query" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{}],
    });
    expect(await arbac.evaluate({ resource: "t", action: "remove" }, user)).toStrictEqual({
      allowed: false,
    });
  });

  it("re-registering a role resets its memoized matches", async () => {
    const arbac = new Arbac<Attrs, Scope>().registerRole({
      id: "r",
      rules: [{ resource: "t", action: "query" }],
    });
    const user = { id: "u", roles: ["r"], attrs: { tenant: "x" } };
    expect((await arbac.evaluate({ resource: "t", action: "query" }, user)).allowed).toBe(true);
    arbac.registerRole({ id: "r", rules: [{ resource: "t", action: "query", effect: "deny" }] });
    expect(await arbac.evaluate({ resource: "t", action: "query" }, user)).toStrictEqual({
      allowed: false,
    });
    arbac.registerRole({
      id: "r",
      rules: [{ resource: "t", action: "*", scope: (a: Attrs) => ({ tag: a.tenant }) }],
    });
    expect(await arbac.evaluate({ resource: "t", action: "query" }, user)).toStrictEqual({
      allowed: true,
      scopes: [{ tag: "x" }],
    });
  });

  it("stays correct past the per-role memo bound", async () => {
    const arbac = new Arbac<Attrs, Scope>().registerRole({
      id: "r",
      rules: [
        { resource: "t", action: "keep.*" },
        { resource: "t", action: "keep.secret", effect: "deny" },
      ],
    });
    const user = { id: "u", roles: ["r"], attrs: { tenant: "x" } };
    for (let i = 0; i < 1500; i++) {
      const allowed = (await arbac.evaluate({ resource: "t", action: `keep.a${i}` }, user)).allowed;
      expect(allowed).toBe(true);
    }
    expect((await arbac.evaluate({ resource: "t", action: "keep.secret" }, user)).allowed).toBe(
      false,
    );
    expect((await arbac.evaluate({ resource: "t", action: "other" }, user)).allowed).toBe(false);
  });

  it("resolves attrs once per pass, only when a matching rule has a scope", async () => {
    const arbac = new Arbac<Attrs, Scope>().registerRole({
      id: "r",
      rules: [
        { resource: "t", action: "q", scope: (a: Attrs) => ({ tag: `1${a.tenant}` }) },
        { resource: "t", action: "q", scope: (a: Attrs) => ({ tag: `2${a.tenant}` }) },
        { resource: "t", action: "open" },
      ],
    });
    const attrs = vi.fn(async () => ({ tenant: "x" }));
    expect(
      await arbac.evaluate({ resource: "t", action: "q" }, { id: "u", roles: ["r"], attrs }),
    ).toStrictEqual({ allowed: true, scopes: [{ tag: "1x" }, { tag: "2x" }] });
    expect(attrs).toHaveBeenCalledTimes(1);
    await arbac.evaluate({ resource: "t", action: "open" }, { id: "u", roles: ["r"], attrs });
    expect(attrs).toHaveBeenCalledTimes(1);
  });
});
