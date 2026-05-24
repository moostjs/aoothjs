# Workflow conventions (auth-moost)

Canonical reference: [LoginWorkflow](src/workflows/login.workflow.ts) (commits `2035079` + `da121a6`). `InviteWorkflow` and `RecoveryWorkflow` will be migrated to the same shape.

## Layering — what lives where

| Concern                                                               | Lives on                            | Read/write surface               |
| --------------------------------------------------------------------- | ----------------------------------- | -------------------------------- |
| Infrastructure (TTLs, cookie names, form schemas, magic-link timeout) | `LoginWorkflowOpts`                 | `this.opts.<infra-group>.<flag>` |
| Policy (per-tenant / per-request / per-user flags)                    | `protected resolveXxx(ctx)` getters | Override seam                    |
| Resolved policy (set by `prepare-<group>` @Step)                      | `ctx.<group>?.<flag>`               | Schema conditions + step bodies  |
| Per-event state (form input, step decisions)                          | `ctx.<field>`                       | Step bodies                      |

**`LoginWorkflowOpts` is infrastructure-only.** Policy NEVER lives on opts. If a knob varies by request/tenant/user, it goes on a `resolveXxx()` method.

## `resolveXxx(ctx)` — policy getter convention

The customer override surface for context-varying policy. **One resolver per option group.** Group all resolveXxx methods under a single labeled block (`// ── Resolved policy surface ──`) for discoverability.

```ts
protected resolveAcceptance(_ctx: LoginWfCtx):
  NonNullable<LoginWfCtx["acceptance"]> | Promise<NonNullable<LoginWfCtx["acceptance"]>> {
  return { profileCompleteRequired: false, consentMarketing: false };
}
```

Rules:

- Return type is the `T | Promise<T>` union — **never** `async` on the default impl.
- Defaults are hardcoded in the resolver body (policy no longer lives on opts).
- Customers override with `async resolveXxx()` for async work; `Promise<T>` is a subtype of the union, so TS accepts the override.
- **NEVER** use `resolveXxx` as a `@Step` id or a `@Step` handler method name. `resolveXxx` is exclusively for getter methods.

## `prepare-<group>` @Step — call resolver, write ctx

Each resolveXxx has a paired `@Step("prepare-<kebab>")` that calls it and writes the result to `ctx.<group>`. The body branches on `result instanceof Promise` to preserve the engine's sync fast path:

```ts
@Step("prepare-acceptance")
prepareAcceptance(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
  const result = this.resolveAcceptance(ctx);
  if (result instanceof Promise) {
    return result.then((r) => { ctx.acceptance = r; return undefined; });
  }
  ctx.acceptance = result;
  return undefined;
}
```

- Method name: `prepareXxx` (camelCase).
- @Step id: `prepare-<kebab-group>`.

## @Step return type — `T | Promise<T>` union

Default sync `@Step` bodies type the return as `T | Promise<T>` so customer subclasses can override with `async`:

```ts
init(ctx): undefined | Promise<undefined> { return undefined; }                 // sync default
selectMfaMethod(ctx): undefined | Promise<undefined> { ... }                    // sync default
magicLinkRequest(): void | Promise<void> { throw new HttpError(501, ...); }     // stub throws
```

The wf engine awaits **only when the actual return value is a Promise**. Adding `async` to a default impl forces every default call to allocate a Promise, defeating the framework's sync fast-path optimization.

## Step IDs

- **kebab-case**: `prepare-mfa-setup`, `ensure-email`, `pincode-send-login`.
- **Workflow-scoped prefix** when at risk of cross-workflow collision: `login-enroll-*`, `invite-*`, `recovery-*`. The wf engine registers `@Step("id")` globally — duplicate ids silently overwrite.
- **TS method names stay camelCase** (TS convention). The @Step id and the method name are independent — the engine matches by id string. Don't rename methods just because an id changed.

## Schema organization

Use `@prostojs/wf` subflow grouping `{ condition, steps: [...] }` to hoist shared conditions. Use `{ break: (ctx) => cond }` after abort sites to short-circuit cleanly rather than repeating `!ctx.aborted` on every downstream step.

Engine semantics (verified in `@prostojs/wf` source):

- A subflow's `condition` is evaluated **once** when the engine reaches it — NOT re-evaluated for each sibling inside the subflow.
- `break: cond` exits the immediately enclosing `for` loop (and propagates out of `while`).
- `while: cond` is re-evaluated each iteration.

Only hoist conditions that are **stable for the duration of the subflow's execution**:

| Pattern                                                                         | Hoist?                                                    | Why                                     |
| ------------------------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------- |
| `(ctx.mfaMethod === "sms" \|\| ctx.mfaMethod === "email")` for the pincode pair | ✅                                                        | mfaMethod doesn't flip inside the pair  |
| `enrolledMethods === 0` for the forced-enrollment trio                          | ✅                                                        | Stable for the trio's duration          |
| `!ctx.aborted` across Phase 5+ steps                                            | ❌ — use `{ break: !!ctx.aborted }` after each abort site | Abort flips mid-subflow                 |
| `!ctx.username` after `credentials`                                             | ❌ — use `{ break: !ctx.username }` once                  | 5 alt-action paths bypass username      |
| `!ctx.mfaChecked` inside the MFA while-loop                                     | ❌ — keep per-step                                        | Sibling steps may flip it mid-iteration |

## `prepare-*` placement in the schema

All prepare-\* steps run AFTER `credentials` and the `{ break: !ctx.username }` gate (so resolvers can read `ctx.username` for user-specific overrides), but BEFORE any policy-using step.

**Exception — `credentials` runs BEFORE the username gate**, so it cannot rely on prepare-_. It inline-calls `resolveAlternateCredentials(ctx)` + `resolveGuards(ctx)` (the two policies it needs for alt-action routing and `passwordInitial` detection). Later prepare-_ steps idempotently re-write the same values once username is set.

## Helpers stay strictly sync

Protected methods called from default @Step bodies stay sync-only — do NOT widen them to `T | Promise<T>`:

```ts
protected resolveRecoveryUrl(username: string | undefined, alt: ...): string { ... }
protected resolveRedirect(ctx): string | undefined { ... }
```

If a customer needs async logic in a helper, they override the **calling @Step**, not the helper. Widening helper return types would force `await` at default call sites and defeat the sync fast path.

`load*` methods (`loadTenants`, `loadPersonas`, `loadActiveSessions`) stay async because they hit external stores — but they're **data fetchers**, not policy resolvers. Do NOT rename them to `resolveXxx`.

## DI scope — SINGLETON by default

`@Controller()` implies `@Injectable(true)` (SINGLETON). Workflow base classes hold no per-event mutable state on `this` — per-event state lives on `ctx` + wooks composables — so one instance per app lifetime is correct. Don't add `@Injectable("FOR_EVENT")` to base workflow classes.

**Add `@Injectable("FOR_EVENT")` ONLY when**:

- The constructor reads request-scoped composables (e.g. `useHeaders()` in the ctor to pick a variant config).
- The class holds per-event state on instance properties.

moost@0.6.x does NOT inherit `@Injectable` across `extends`, so each subclass must re-apply its scope decorator if it needs one. Subclasses inheriting from a SINGLETON workflow can drop `@Injectable` entirely — `@Controller()` provides the implicit SINGLETON.

## `@Public()` — per-workflow decision

`@Public()` on the workflow class bypasses arbac (RBAC/authz) on workflow events. It's the right default ONLY for workflows that anonymous users must be able to start:

- ✅ `LoginWorkflow` — class-level `@Public()`. Users authenticating have no token yet.
- ✅ `RecoveryWorkflow` — class-level `@Public()`. Same rationale.
- ❌ `InviteWorkflow` — NO class-level `@Public()`. The admin invite phase requires an authenticated admin with `invite` permission; the invitee-accept phase runs on a magic-link token (different auth surface, handled per-step).

Pick the default by asking: **can an anonymous request legitimately start this workflow?** If yes, class-level `@Public()`. If no, leave it off and let arbac evaluate normally.

Regardless of the class-level decision, do NOT repeat `@Public()` on individual `@Step` methods — the class-level decoration (or its absence) is the entire `arbac` policy surface for the workflow.

## Wooks composables for event-context access

```ts
const { referer } = useHeaders(); // ✅ composable resolves current() itself
const cookie = useCookies().getCookie("name"); // ✅
const req = useRequest() as unknown as { headers? }; // ❌ duck-typing
```

Don't pass `current()` explicitly — every composable resolves the active event context on its own. The only reason to thread it through is micro-optimization when calling many composables in one handler:

```ts
const c = current();
const { referer } = useHeaders(c);
const cookies = useCookies(c);
const res = useResponse(c);
```

If a composable exists for what you need, use it. Don't cast `req`/`res` objects to custom shapes.

## Subclass extension pattern (consumer-facing)

```ts
@Inherit()
@Controller() // SINGLETON; add @Injectable("FOR_EVENT") ONLY if ctor reads composables
class MyLogin extends LoginWorkflow {
  constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
    super(opts, users, auth); // re-declared so TS emits design:paramtypes
  }

  protected resolveAcceptance(ctx: LoginWfCtx) {
    return { profileCompleteRequired: this.tenantRequiresProfile(), consentMarketing: false };
  }

  protected async resolveMultiContext(ctx: LoginWfCtx) {
    return {
      tenantSelect: await this.tenantsDb.userHasMultiple(ctx.username!),
      personaSelect: false,
    };
  }
}
```

Subclass MUST:

- Re-apply `@Inherit() @Controller()` (and `@Injectable("FOR_EVENT")` only if the ctor needs composables).
- Re-declare the constructor signature — TS emits fresh `design:paramtypes` metadata per class; without an explicit ctor, moost can't resolve DI.

## Adding a new policy group

1. Add an optional field on `LoginWfCtx`: `xxxxx?: { ... };`.
2. Add a `LoginPolicyOverrides` field (if the group should be customer-overridable via the harness/variants pattern).
3. Add a protected resolver `resolveXxxxx(ctx)` in the `// ── Resolved policy surface ──` block. Return type: `NonNullable<LoginWfCtx["xxxxx"]> | Promise<NonNullable<LoginWfCtx["xxxxx"]>>`. Default body returns hardcoded values.
4. Add the `@Step("prepare-xxxxx")` method with the Promise-branched body (mirror an existing one).
5. Add `{ id: "prepare-xxxxx" }` to the schema, AFTER `credentials`/`!ctx.username` gate, BEFORE any policy-using step.
6. Schema conditions and step bodies read `ctx.xxxxx?.<flag>`.

## Testing conventions

- `prepareWfApp({ loginPolicy: { <group>: {...} } })` to override policy groups (the new harness knob).
- `prepareWfApp({ loginOpts: { <infra-field>: ... } })` is ONLY for infrastructure (`mfa.pincodeLength`, `forms`, etc.).
- For subclass tests: use the `makeLoginSubclass({ resolveXxx: ... })` helper in `__test__/workflows.login.options.spec.ts`.
- Async-resolver behavior is pinned by the regression test `async resolveXxx is awaited` in `__test__/workflows.login.subclass.spec.ts`. If a refactor breaks the `result instanceof Promise` branch in `prepare-*`, that test fails.

## What NOT to do

- ❌ `async` keyword on default `@Step` bodies (forces Promise allocation; breaks fast path).
- ❌ `await this.resolveXxx(ctx)` in default @Step bodies (same problem).
- ❌ Reading `this.opts.<policy-group>.<flag>` (policy lives on resolvers, not opts).
- ❌ Adding policy flags back to `LoginWorkflowOpts`.
- ❌ Per-method `@Public()` when the class is already `@Public()`.
- ❌ Duck-typed casts on wooks event-context objects.
- ❌ Repeating `!ctx.aborted` / `!!ctx.username` on every downstream step — use `{ break: ... }` gates.
- ❌ Renaming `loadTenants` / `loadPersonas` / `loadActiveSessions` to `resolveXxx` (data fetchers, not policy resolvers).
- ❌ Using `resolveXxx` as a `@Step` id or `@Step` handler method name.
- ❌ Widening helper return types (`resolveRecoveryUrl`, `resolveRedirect`) to `T | Promise<T>` — stay strictly sync; consumers needing async override the calling @Step.
