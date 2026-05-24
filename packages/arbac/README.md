<p align="center">
  <a href="https://aooth.moost.org">
    <img src="https://aooth.moost.org/logo.svg" alt="aoothjs" width="120" />
  </a>
</p>

<h1 align="center">@aooth/arbac</h1>

<p align="center">
  Batteries-included RBAC — re-exports <code>@aooth/arbac-core</code> and adds a fluent role builder, reusable privilege factories, scope-merge utilities, and a codegen CLI for typed resource/action unions.
</p>

<p align="center">
  <a href="https://aooth.moost.org/arbac/"><strong>Documentation →</strong></a>
</p>

---

## Install

```bash
pnpm add @aooth/arbac
```

## Documentation

Full docs, API reference, and recipes: **https://aooth.moost.org/arbac/**

- [Concepts](https://aooth.moost.org/arbac/concepts)
- [Role builder](https://aooth.moost.org/arbac/builder)
- [Privilege factories](https://aooth.moost.org/arbac/privileges)
- [Scope merging](https://aooth.moost.org/arbac/scopes)
- [Codegen CLI](https://aooth.moost.org/arbac/codegen)
- [API reference](https://aooth.moost.org/api/arbac)

## Deny is binary on (resource, action)

`.deny(resource, action)` short-circuits the entire `(resource, action)` tuple — there is no scope or filter parameter. Once a deny rule's action regex matches, `evaluate()` returns `{ allowed: false }` immediately, before any other role's `allow` scopes are even constructed (see `arbac-core/src/arbac.ts:126-131`).

If you need "hide rows where condition X", express it as an `allow` with a filter that excludes X, not as a partial deny:

```ts
// ✗ Not supported — no row-level deny.
// .deny("tasks", "query", { scope: { filter: { status: "secret" } } })

// ✓ Use a filtered allow instead.
allowTableRead<UserAttrs, Scope>("tasks", {
  scope: (attrs) => ({
    filter: { tenantId: attrs.tenantId, status: { $ne: "secret" } },
  }),
});
```

Pinned by `UNION-03` and `UNION-05` in `packages/e2e-demo/test/arbac-union.spec.ts` — unscoped deny short-circuits sibling allows, and wildcard `.deny("tasks", "*")` 403s both row-allow (`markDone`) and set-allow (`new`) tuples.

## Scopes from multiple roles union via `$or` — permissive wins

When a user has multiple roles that each `allow` the same `(resource, action)`, their scopes are merged disjunctively via `mergeScopeFilters` (see `packages/arbac/src/scope/filter.ts`). A row matches if ANY scope's filter matches. Consequence: if one scope has no filter (rule registered without `scope`, or with `filter: undefined` / `filter: {}`), the union widens to universe and the more restrictive filters in sibling scopes are silently dropped.

```ts
// Role "viewer" — tenant-scoped read on tasks.
.use(allowTableRead("tasks", {
  scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }),
}))

// Role "tasks-everywhere" — unscoped read on tasks (e.g., for an audit role).
.allow("tasks", "query")  // no scope ← contributes universe to the union

// A user with both roles sees ALL tasks (universe wins), not just their tenant.
```

This is the natural `$or` semantic: union of "tenant rows" and "all rows" is "all rows". The takeaway: don't grant an unscoped allow on a resource that other roles are trying to filter. Pinned by the `transformArbacFilter` empty-vs-undefined coercion tests in `packages/arbac-moost/src/db/shared-read-helpers.spec.ts`.

## License

MIT
