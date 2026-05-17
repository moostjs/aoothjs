# Mental Model

This page answers: _what concepts does the ARBAC engine actually compute over, and what are the rules that make `allowed: true|false` come out one way or the other?_ Read this once before touching the API.

## Vocabulary

| Term                  | Definition                                                                                                                                                                     |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ |
| **Role**              | A named container of rules, identified by `id` (e.g. `com.role.editor`). Stored on `Arbac` via `registerRole(role)`.                                                           |
| **Rule**              | One of two shapes — `{ resource, action, scope? }` (allow, the default) or `{ resource, action, effect: 'deny' }` (deny).                                                      |
| **Resource**          | A dotted string ID (e.g. `com.resource.db.user`, or just `articles`). Free-form; conventionally namespaced.                                                                    |
| **Action**            | A verb string (`read`, `create`, `whatever-action`, `*`).                                                                                                                      |
| **Effect**            | `'allow'` — implicit when `effect` is omitted — or `'deny'`. There is no explicit `'allow'` literal in the type; allow is the absence of `effect`.                             |
| **Scope**             | An app-defined object returned by a rule's `scope()` callback. The engine **never inspects it** — it just pushes scopes into an array. Callers interpret them as data filters. |
| **Universe sentinel** | An empty `{}` that the engine pushes into the scope array whenever an allow rule has _no_ scope function. Callers must read `{}` as "no restriction".                          |
| **User attrs**        | A generic `TUserAttrs` object passed to the engine at evaluation time. Scope functions receive it as their first argument. Can be a value or a `(userId) => TUserAttrs         | Promise<TUserAttrs>` resolver. |
| **Context**           | There is no separate context object. The only dynamic input scope functions receive is `(userAttrs, userId)`.                                                                  |
| **Condition**         | Not a distinct concept. Conditional rules are expressed by writing logic inside a scope function or by splitting rules.                                                        |

## The evaluation question

`arbac.evaluate(res, user)` answers: _given this user's role IDs and attrs, is the action allowed on the resource — and if so, what data scopes apply?_

```ts
type TArbacEvalResult<TScope> =
  | { allowed: false } // denied, no scopes key at all
  | { allowed: true; scopes: TScope[] }; // allowed, with the union of every matching allow rule's scope
```

The `scopes` key is **only** present when `allowed === true`. It is `TScope[]`, never `undefined` in that branch.

## Allow-vs-deny semantics

Two kinds of rule, two passes:

1. **Deny pass first.** Iterate every resolved role's deny list. If _any_ deny rule matches the requested `(resource, action)`, return `{ allowed: false }` immediately.
2. **Allow pass.** Iterate every resolved role's allow list. For each match, push a scope onto the result array (`{}` if the rule has no `scope` fn; otherwise the fn's return value).

::: warning Deny wins, absolutely
There is **no specificity weighting**. A wildcard `deny('**', '*')` cancels a hand-crafted `allow('articles', 'read')` regardless of how specific or how recent the allow rule is. If you write a deny, mean it.
:::

## Multi-role scope union

A user can have multiple role IDs. The engine resolves them all, runs the deny pass against the _combined_ deny lists, then runs the allow pass against the _combined_ allow lists. Every matching allow rule contributes one element to `scopes`.

Two consequences:

- The result `scopes` array is **always a UNION** in the caller's interpretation. Caller code typically maps it to `{ $or: scopes }` for an OR filter — or uses [`mergeScopeFilters`](./scopes#mergescopefilters) to do that cleanly.
- The array can grow unbounded with overlapping rules. Deduplication is the caller's job.

## The universe sentinel

When an allow rule has no `scope` function, the engine pushes `{}`. In a union, `{}` is interpreted as _no restriction_ — i.e. it widens the union to "everything".

```ts
// Two roles, one bounded, one unbounded.
defineRole()
  .id("regional")
  .allow("articles", "read", (a) => ({ region: a.region }));
defineRole().id("admin").allow("articles", "read"); // no scope fn

// Evaluating with both roles → scopes: [{ region: 'EMEA' }, {}]
// Caller sees `{}` and concludes: no filter — admin overrides the regional bound.
```

This is the contract `mergeScopeFilters` (and similar utilities) implement: an empty filter in the union short-circuits to "no constraint at all".

## Empty-roles short-circuit

```ts
await arbac.evaluate(res, { id: 'u1', roles: [], attrs: {...} })
// → { allowed: false }    // no scopes key, period.
```

If `user.roles` is empty (or only contains role IDs the engine has never seen), no deny or allow pass runs. The result is `{ allowed: false }` with no `scopes` key. The engine also `console.warn`s **once per unknown role ID** the user is assigned — useful in dev, not noisy in prod. An empty `user.roles` array produces no warning.

## Wildcard matching

Patterns use shell-glob style with `.` as the segment separator:

| Pattern             | Compiled regex               | Matches                                              | Doesn't match              |
| ------------------- | ---------------------------- | ---------------------------------------------------- | -------------------------- |
| `*`                 | `^[^.]*$`                    | `read`, `whatever-action`                            | `db.read`                  |
| `com.resource.db.*` | `^com\.resource\.db\.[^.]*$` | `com.resource.db.user`                               | `com.resource.db.fin.docs` |
| `com.resource.**`   | `^com\.resource\..*$`        | `com.resource.db.user`, `com.resource.fin.docs.line` | `com.resource`             |
| `**`                | `^.*$`                       | anything                                             | nothing                    |

`*` matches inside one dotted segment; `**` matches across segments. The implementation is five lines — see [`arbacPatternToRegex`](./core#arbacpatterntoregex) on the Core page.

::: warning Action `*` does **not** match dotted actions
`action: '*'` compiles to `^[^.]*$` and won't match `db.read`. If you want to wildcard a namespaced action, write `action: '**'`.
:::

## Worked precedence example

```ts
// One user, two roles.
const reader = defineRole().id("reader").allow("articles", "read").build();
const banned = defineRole().id("banned").deny("articles", "*").build();

const arbac = new Arbac();
arbac.registerRole(reader).registerRole(banned);

await arbac.evaluate(
  { resource: "articles", action: "read" },
  { id: "u1", roles: ["reader", "banned"], attrs: {} },
);
// → { allowed: false }
```

The `banned` role's wildcard deny runs first and wins, even though `reader` has an exact-match allow. Order of `.registerRole()` calls doesn't change the outcome — there is no notion of role priority.

## What is NOT in the engine

A short list of features ARBAC does **not** ship — by design, since they all reduce to writing rules differently:

- **Conditions as a first-class concept.** Conditions live inside scope functions, or as a deny rule with a tight resource/action pattern.
- **Role inheritance.** Roles compose by listing a user with multiple `roles[]`, not by one role extending another. (The [Builder](./builder)'s `.use()` method approximates inheritance at construction time by splicing privilege rules in.)
- **Specificity weighting.** Deny always wins.
- **Action namespaces.** Actions are flat strings. Dotted actions like `db.read` work but require `**` to wildcard.

## Next

Now that the vocabulary and semantics are clear, the [Core Engine](./core) page covers the `Arbac` class itself, its constructor, the evaluation steps in implementation order, and the type shapes returned. Or skip ahead to the [Builder API](./builder) if you want to start writing roles.
