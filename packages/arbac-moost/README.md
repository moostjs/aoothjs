<p align="center">
  <a href="https://aooth.moost.org">
    <img src="https://aooth.moost.org/logo.svg" alt="aoothjs" width="120" />
  </a>
</p>

<h1 align="center">@aooth/arbac-moost</h1>

<p align="center">
  Moost RBAC integration — DI-injectable <code>MoostArbac</code>, an authorize interceptor, <code>@ArbacResource</code> / <code>@ArbacAction</code> decorators, <code>AsArbacDbController</code> for scoped DB controllers, and auto-wired provider plumbing for <code>.as</code> user models.
</p>

<p align="center">
  <a href="https://aooth.moost.org/moost/"><strong>Documentation →</strong></a>
</p>

---

## Install

```bash
pnpm add @aooth/arbac-moost @aooth/arbac @aooth/user
```

## Documentation

Full docs, API reference, and recipes: **https://aooth.moost.org/moost/**

- [Setup](https://aooth.moost.org/moost/setup)
- [`@ArbacAuthorize`](https://aooth.moost.org/moost/arbac-authorize)
- [DB controllers (`AsArbacDbController`)](https://aooth.moost.org/moost/db-controllers)
- [Atscript wiring (`@arbac.*` annotations)](https://aooth.moost.org/moost/atscript)
- [Decorators](https://aooth.moost.org/moost/decorators)
- [API reference](https://aooth.moost.org/api/arbac-moost)

## Custom action handlers — your responsibility

The `@ArbacAuthorize` interceptor gates the **entry** to a `@DbAction` handler: if the user lacks the privilege, the handler doesn't run. But what the handler does inside its body is on you — the interceptor doesn't follow secondary database calls or external side effects.

If your handler reads or writes rows from the same table the entry-gate scopes, route those calls through the active scope. `useArbac().getScopes<ArbacDbScope>()` exposes the per-event scope array; from there:

- `scope.filter` — AND-merge into your WHERE clause (use the union of all scope filters via `mergeScopeFilters` from `@aooth/arbac`, not just the first).
- `scope.set` — overlay onto any insert/update payload **after** your own body keys, so scope-set wins over caller-supplied values.
- `scope.projection` — restrict any custom SELECT to the union of allowed fields.

The demo at [`packages/e2e-demo/src/controllers/_helpers.ts`](../e2e-demo/src/controllers/_helpers.ts) shows the convention (`scopedFilter`, `scopedSet`); the test `ACT-08` in [`packages/e2e-demo/test/arbac-actions.spec.ts`](../e2e-demo/test/arbac-actions.spec.ts) pins that handlers using this pattern correctly enforce row-level scope.

If your handler talks to a different system (audit log, cache, external API, sibling table) or has special logic (cross-tenant aggregations, admin escape hatches), you wire the scope to whatever surface that system exposes — there is no automatic propagation, and the trust decisions stay explicit in the handler.

> **Why not enforce structurally?** The framework can't know, at the action-entry point, what the handler intends to read or write. A handler that calls a remote service, spans transactions across tables, or has admin-only branches won't compose cleanly with an automatic row-level gate. Keeping scope enforcement explicit makes the trust decision a code-review-visible artifact. The tradeoff is that a forgetful contributor can bypass it — mitigate via code review and ACT-08-style regression tests.

## License

MIT
