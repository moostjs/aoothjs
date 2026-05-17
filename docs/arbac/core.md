# Core Engine

This page answers: _what does the `Arbac` class actually expose, what does `evaluate()` do step by step, and what are the type shapes you can rely on?_ It documents [`@aooth/arbac-core`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac-core) — the zero-dependency engine.

`@aooth/arbac` re-exports everything here verbatim, so you can import `Arbac` from either package.

## `class Arbac<TUserAttrs, TScope>`

The evaluator. Holds a registry of roles and resources, pre-compiles per-resource allow/deny lists for each role, and answers `evaluate()` queries.

```ts
class Arbac<TUserAttrs extends object, TScope extends object> {
  constructor();
  registerRole(role: TArbacRole<TUserAttrs, TScope>): this;
  registerResource(resource: string): this;
  evaluate<T extends string | undefined>(
    res: { resource: string; action: string },
    user: {
      id: T;
      roles: string[];
      attrs: TUserAttrs | ((id: T) => TUserAttrs | Promise<TUserAttrs>);
    },
  ): Promise<TArbacEvalResult<TScope>>;
}
```

Two generics:

- `TUserAttrs` — the shape of the per-user attribute bag passed to scope functions. Constrained to `object`.
- `TScope` — the shape of the scope objects rules emit. Constrained to `object`. Choose one stable shape across all rules so the union in `scopes: TScope[]` is homogeneous.

### Constructor

`new Arbac()` — takes no arguments. There is nothing to configure.

```ts
import { Arbac } from "@aooth/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const arbac = new Arbac<Attrs, Scope>();
```

### `registerRole(role): this`

Stores the role in the internal `roles[id]` map and re-evaluates the role against every already-registered resource. Idempotent: re-registering the same `id` overwrites.

```ts
arbac.registerRole({
  id: "editor",
  name: "Editor",
  description: "Can read and update articles in their department.",
  rules: [
    { resource: "articles", action: "read" },
    { resource: "articles", action: "update", scope: (a) => ({ dept: a.dept }) },
    { resource: "articles", action: "publish", effect: "deny" },
  ],
});
```

Returns `this`, so calls chain: `arbac.registerRole(a).registerRole(b)`.

### `registerResource(resource): this`

Idempotent — no-op if the resource is already registered. Otherwise it re-evaluates every known role against the resource, caching the matching allow/deny lists.

`evaluate()` auto-calls this for the resource it's asked about, so **explicit pre-registration is rarely needed**. The one reason to call it is to pre-warm caches at startup.

::: warning Long-lived processes with unbounded resource IDs
Because `evaluate()` auto-registers the resource it sees, the internal `resources` map grows unboundedly if you keep evaluating against new resource IDs. In short-lived workers this is fine; in long-running services with high-cardinality resources, register a finite set of resource _patterns_ via roles (using `**`) and avoid synthesising per-entity resource IDs.
:::

### `evaluate(res, user): Promise<TArbacEvalResult<TScope>>`

Async because `user.attrs` may be a lazy `(userId) => Promise<TUserAttrs>` resolver.

```ts
const result = await arbac.evaluate(
  { resource: "articles", action: "update" },
  {
    id: "u1",
    roles: ["editor"],
    attrs: { dept: "sales" },
  },
);
// → { allowed: true, scopes: [{ dept: 'sales' }] }
```

With a lazy attrs resolver:

```ts
await arbac.evaluate(
  { resource: "articles", action: "read" },
  {
    id: "u1",
    roles: ["editor"],
    attrs: async (id) => loadUserAttrs(id), // called at most once per evaluate()
  },
);
```

The resolver is invoked the first time _any_ matching scope function needs `userAttrs`. Subsequent scope functions in the same `evaluate()` call reuse the cached value.

## Evaluation algorithm

The implementation runs these steps, in order:

1. **Ensure the resource is registered** (auto-register if new) so per-role allow/deny lists exist.
2. **Resolve the user's roles** by lookup in `resources[resource][roleId]`. Unknown role IDs emit `console.warn` **once** per role ID (per process).
3. **Empty-roles short-circuit.** If no resolved roles, return `{ allowed: false }` with no `scopes` key.
4. **Deny pass — first.** Iterate every resolved role's deny list; if any pre-compiled `_actionRegex` matches the requested action, return `{ allowed: false }` immediately.
5. **Allow pass.** Iterate every resolved role's allow list. For each match:
   - If the rule has a `scope` fn — lazily resolve `userAttrs`, then push `rule.scope(userAttrs, String(user.id))`.
   - Otherwise push `{}` (the universe sentinel).
6. **Return** `allowed ? { allowed: true, scopes } : { allowed: false }` (branches on the `allowed` flag — at least one allow rule matched — not on `scopes.length`; a universe-sentinel `{}` still counts as a match).

A few invariants follow directly:

- Deny precedes allow. There is no specificity weighting.
- No precedence among roles. Allow scopes from multiple roles are concatenated.
- `user.id` is stringified before being passed to scope fns: `rule.scope(userAttrs, String(user.id))`.

::: info Implementation notes
The engine mutates rule objects during pre-compilation to attach internal regex caches. Don't `Object.freeze()` rule literals before registration.
:::

## Type reference

### `TArbacEvalResult<TScope>`

```ts
interface TArbacEvalResult<TScope> {
  allowed: boolean;
  scopes?: TScope[]; // present only when allowed === true
}
```

Practical pattern for callers:

```ts
const r = await arbac.evaluate(res, user);
if (!r.allowed) throw new ForbiddenError();
applyToQuery(r.scopes); // TS narrows scopes to TScope[]
```

### `TArbacRole<TUserAttrs, TScope>`

```ts
interface TArbacRole<TUserAttrs, TScope> {
  id: string;
  name?: string;
  description?: string;
  rules: Array<TArbacRule<TUserAttrs, TScope>>;
}
```

`id` is the lookup key. `name` and `description` are for UIs and audit logs — the engine doesn't read them.

### `TArbacRule<TUserAttrs, TScope>`

A discriminated union, distinguished by the presence of `effect`:

```ts
type TArbacRule<TUserAttrs, TScope> =
  | {
      resource: string;
      action: string;
      scope?: (userAttrs: TUserAttrs, userId: string) => TScope;
      effect?: never; // allow (implicit)
    }
  | {
      resource: string;
      action: string;
      effect: "deny";
      scope?: never; // deny can never carry a scope
    };
```

Two consequences:

- A `deny` rule **cannot** carry a `scope`. A deny is total — it answers `{ allowed: false }` end of story.
- An allow rule cannot set `effect: 'allow'` explicitly. The implementation falls back to `'allow'` when `effect` is missing; the type forbids the literal.

## `arbacPatternToRegex(input: string): RegExp`

```ts
function arbacPatternToRegex(input: string): RegExp;
```

The wildcard matcher exposed for inspection or reuse. `*` matches a single dot-separated segment; `**` matches across segments. The `.` separator is hard-coded.

```ts
import { arbacPatternToRegex } from "@aooth/arbac";

arbacPatternToRegex("com.resource.db.*");
// → /^com\.resource\.db\.[^.]*$/
```

## Worked example — two roles, three scopes

A user has both an `editor` role bounded to their department and a `regional` role bounded to their region. They request `update` on `articles`.

```ts
type Attrs = { dept: string; region: string };
type Scope = { dept?: string; region?: string };

const arbac = new Arbac<Attrs, Scope>();

arbac.registerRole({
  id: "editor",
  rules: [
    { resource: "articles", action: "read" },
    { resource: "articles", action: "update", scope: (a) => ({ dept: a.dept }) },
    { resource: "articles", action: "publish", effect: "deny" },
  ],
});

arbac.registerRole({
  id: "regional",
  rules: [
    { resource: "articles", action: "*", scope: (a) => ({ region: a.region }) },
    { resource: "articles", action: "delete", effect: "deny" },
  ],
});

await arbac.evaluate(
  { resource: "articles", action: "update" },
  {
    id: "u1",
    roles: ["editor", "regional"],
    attrs: { dept: "sales", region: "EMEA" },
  },
);
// → {
//     allowed: true,
//     scopes: [
//       { dept:   'sales' },     // from editor.update
//       { region: 'EMEA'  },     // from regional.*
//     ],
//   }
```

The caller now decides how to apply both scopes to a query. The UNION interpretation says: _articles in `sales` dept OR articles in `EMEA` region_. That's typically not what you want — you want the **intersection** ("must be both"). That intersection is the application layer's job, often expressed by emitting `{ dept, region }` from a single scope fn rather than two rules. See [Scope Merging](./scopes) for the multi-role union utilities.

Calling `evaluate()` with `action: 'publish'` returns `{ allowed: false }` (editor's explicit deny wins). Calling with `action: 'delete'` also returns `{ allowed: false }` (regional's deny wins, even though no allow rule matched anyway).

## Gotchas

- **Unknown roles warn once.** First time an unknown role ID is requested, the engine logs once. Useful in dev — confirm role IDs at boot.
- **Scopes array can grow unbounded.** N matching allow rules across roles produce N scope entries. Deduplicate (or merge) at the caller — see [Scope Merging](./scopes).
- **No `scopes` key when allowed is false.** Don't write `r.scopes?.length` to mean "denied"; write `!r.allowed`.
- **`{}` is not "no access".** It's the universe sentinel — "no restriction". Treat it as a wildcard widener inside a union.
- **Stringified `userId`.** Scope fns get `String(user.id)`. Pass `id` already as a string if your store uses string keys.

## Next

- [Builder API](./builder) — replace hand-rolled `TArbacRole` literals with a chainable, generic-aware API.
- [Privilege Factories](./privileges) — bundle related rules into reusable named units.
