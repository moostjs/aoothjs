# Workflow conventions (auth-moost)

Canonical reference: [`AuthWorkflow`](src/workflow/auth-workflow.ts) — one concrete class with **six** `@Workflow` methods. Four are public, dispatched via `POST /auth/trigger` (the `DEFAULT_AUTH_WORKFLOWS` allow-list): `loginFlow` (`auth/login/flow`, incl. the federated SSO leg), `inviteFlow` (`auth/invite/start`), `recoveryFlow` (`auth/recovery/flow`), `signupFlow` (`auth/signup/flow`). Two are ARBAC-gated authenticated self-service flows, each dispatched from its own guarded route and deliberately excluded from the public allow-list: `changePasswordFlow` (`auth/change-password/flow` → `POST /auth/change-password`) and `addMfaFlow` (`auth/add-mfa/flow` → `POST /auth/add-mfa`). Replaces the prior `LoginWorkflow` + `InviteWorkflow` + `RecoveryWorkflow` + `AuthWorkflowBase` quartet.

## Layering — what lives where

| Concern                                                                                                | Lives on                            | Read/write surface               |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------- | -------------------------------- |
| Cross-workflow infra (pincode timers, loginUrl, totpIssuer) + per-workflow infra (cookie names, forms) | `AuthWorkflowOpts`                  | `this.opts.<infra-group>.<flag>` |
| Policy (per-tenant / per-request / per-user flags)                                                     | `protected resolveXxx(ctx)` getters | Override seam                    |
| Resolved policy (set by `prepare-<group>` @Step)                                                       | `ctx.<group>?.<flag>`               | Schema conditions + step bodies  |
| Per-event state (form input, step decisions)                                                           | `ctx.<field>`                       | Step bodies                      |

**`AuthWorkflowOpts` is infrastructure-only.** Policy NEVER lives on opts. If a knob varies by request/tenant/user, it goes on a `resolveXxx()` method.

## `AuthWorkflowOpts` + `ResolvedAuthWorkflowOpts`

`AuthWorkflowOpts` is the user-facing nested-pojo passed to `AuthWorkflow`'s
constructor as `Partial<AuthWorkflowOpts>`. Every field is optional. The
constructor runs `mergeAuthWorkflowOpts(opts)` to produce a
`ResolvedAuthWorkflowOpts` view (every field required, defaults applied)
that step bodies and resolvers read from as `this.opts.<group>.<field>`
without optional chaining.

Cross-workflow infrastructure that the prior shape held in a separate
singleton (`mfa.pincodeLength`, `mfa.pincodeTtlMs`, `mfa.pincodeResendTimeoutMs`,
`loginUrl`, `totpIssuer`) lives directly on the same opts
object — same `this.opts.<field>` access pattern as login-specific infra
(`deviceTrust.cookieName`, `forms.loginCredentials`, …).

**Customer override.** Subclass `AuthWorkflow`, override the relevant
`resolveXxx()` hooks, and pass a merged `Partial<AuthWorkflowOpts>` to
`super(...)`:

```ts
@Inherit()
@Controller() // SINGLETON; add @Injectable("FOR_EVENT") ONLY if ctor reads composables
class MyAuth extends AuthWorkflow {
  constructor(
    opts: Partial<AuthWorkflowOpts>,
    users: UserService,
    auth: AuthCredential,
    consentStore: ConsentStore,
  ) {
    super(
      {
        ...opts,
        mfa: { pincodeLength: 8, pincodeTtlMs: 10 * 60_000, pincodeResendTimeoutMs: 30_000 },
        loginUrl: "/sign-in",
        totpIssuer: "MyApp",
      },
      users,
      auth,
      consentStore,
    );
  }

  protected resolveDeviceTrust(ctx: AuthWfCtx) {
    return { enabled: this.tenantWantsTrustedDevices(), optIn: true, skipsMfa: true };
  }
}

app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, MyAuth]));
```

## Per-flow discrimination — ctx-slot presence, never a flow name

`AuthWfCtx` has **no** `flow` field. The active schema is identified by
which prepare-\* steps have populated which ctx slot. Use this table when
writing a resolver / step body that needs to discriminate:

| Slot present         | Flow                  | Populated by                                       |
| -------------------- | --------------------- | -------------------------------------------------- |
| `ctx.admin`          | invite (admin phase)  | `init-invite-admin` + `prepare-admin-form`         |
| `ctx.accept`         | invite (accept phase) | `init-invite-accept` + `prepare-accept`            |
| `ctx.postReset`      | recovery              | `init-recovery` + `prepare-post-reset`             |
| `ctx.signup`         | self-signup           | `init-signup`                                      |
| `ctx.changePassword` | change-password       | `init-change-password` + `prepare-change-password` |
| `ctx.addMfa`         | add-mfa               | `init-add-mfa`                                     |
| _(none of these)_    | login                 | _(implicit — login is the fallback)_               |

Customer resolver discriminating across flows:

```ts
protected resolveSomething(ctx: AuthWfCtx) {
  if (ctx.admin) return { ...invite-admin-flavored... };
  if (ctx.accept) return { ...invite-accept-flavored... };
  if (ctx.postReset) return { ...recovery-flavored... };
  if (ctx.signup) return { ...signup-flavored... };
  if (ctx.changePassword) return { ...change-password-flavored... };
  if (ctx.addMfa) return { ...add-mfa-flavored... };
  return { ...login-flavored... };
}
```

## Consent persistence — `ConsentStore`

`ConsentStore` is the singleton DI provider holding the customer-defined
consent universe and persistence sink. `AuthWorkflow` takes
`consentStore: ConsentStore` as the **4th** ctor param. All four methods are
no-op defaults — customers extend the class to wire their own behaviour:

- `getPendingConsents(username)` — descriptors for consents the user still
  needs to accept on the next prompt boundary. **User-scoped only.** The
  returned descriptor set MUST NOT vary by workflow name or transport
  channel — every flow that reaches `prepare-consents` consults the same
  user-level universe. OTP channel-ownership consent (which IS channel-
  specific) is captured separately via `recordOtpChannelConsent`.
- `save(username, events)` — persist a batch of captured `ConsentEvent`s.
- `read(username, { id? })` — read consent history, optionally filtered
  by descriptor id.
- `recordOtpChannelConsent(username, channel, target, disclosure)` — fired
  by login's `verify/:channel` step AFTER pincode validation, pinning the
  exact disclosure copy the user saw.

**Customer override.** Extend the class and register the replacement via
moost's `createReplaceRegistry()`:

```ts
@Injectable() // SINGLETON
class MyConsentStore extends ConsentStore {
  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    await db.consents.insertMany(events.map((e) => ({ ...e, username })));
  }
  override async getPendingConsents(username: string | undefined) {
    if (!username) return [];
    const accepted = await db.consents.find({ username, id: "terms" });
    return accepted.some((e) => e.version === "v2")
      ? []
      : [
          {
            id: "terms",
            text: "I accept the updated [Terms](/terms) and [Privacy](/privacy)",
            required: "You must accept the updated terms to continue",
            version: "v2",
          },
        ];
  }
}

app.setReplaceRegistry(createReplaceRegistry([ConsentStore, MyConsentStore]));
```

Singleton scope is required — `@Injectable()` (no scope arg) → SINGLETON.

### OTP-channel disclosure (`resolveOtpDisclosure` + `recordOtpChannelConsent`)

For each OTP-via-email / OTP-via-sms channel the user enrols, `AuthWorkflow`
stages a disclosure paragraph onto `ctx.channel.otpDisclosure` (via the
`resolveOtpDisclosure(ctx, channel)` resolver) BEFORE the
`AskEmailForm` / `AskPhoneForm` carrier-form pause — the SPA reads it via
`@wf.context.pass 'channel'` and renders it adjacent to the email /
phone input so the user reads it BEFORE submitting (the act of typing +
submitting their address constitutes implied consent). The disclosure text
is GENERIC per channel — no target value templated in, since the user
hasn't submitted it yet at ask-time. After the pincode validates AND
`confirmMfaMethod` flips the row to `confirmed: true`, `verify/:channel`
forwards the disclosure string PLUS the verified target to
`consentStore.recordOtpChannelConsent(username, channel, target, disclosure)`
— so the persisted audit record pins BOTH the literal copy shown AND the
address verified.

Default behaviour is **disclosure-only** — legally sufficient for
transactional security codes under TCPA / PECR / CASL / GDPR (legitimate
interest). The default `recordOtpChannelConsent` is a no-op; customers who
need affirmative consent capture (audit-grade record-keeping for legal
disputes or carrier-aggregator requirements) override it to persist.
The `channel` arg is the **protocol** (`'email'` | `'sms'`) — the
user-facing `'phone'` route param is mapped to `'sms'` before the hook
call, so customer impls key on the wire protocol they actually use.

The `prepare-consents` @Step fires once per workflow run, after the
`!ctx.username` break and adjacent to the other prepare-\* steps. It
invokes `consentStore.getPendingConsents(username)` and writes the
returned array to `ctx.consents.pending`. The "always array, never
undefined" invariant is load-bearing — downstream carrier-form gates
read `consents.pending.length > 0` without an `?? []` defensive
fallback. The base method's no-op default returns `[]`, preserving the
invariant for customers who don't override.

## `resolveXxx(ctx)` — policy getter convention

The customer override surface for context-varying policy. **One resolver per option group.** Group all resolveXxx methods under a single labeled block (`// ── Resolved policy surface ──`) for discoverability.

```ts
protected resolveDeviceTrust(_ctx: AuthWfCtx):
  NonNullable<AuthWfCtx["deviceTrust"]> | Promise<NonNullable<AuthWfCtx["deviceTrust"]>> {
  return { enabled: false, optIn: true, skipsMfa: true };
}
```

Most resolvers take a single `ctx` argument. A small number accept extra
positional args alongside `ctx` when the resolved value depends on per-step
input the @Step body knows but ctx doesn't yet carry — e.g.
`resolveOtpDisclosure(ctx, channel)` where the disclosure copy varies by
the route-param channel (`'email'` vs `'phone'`). The argument order stays
**ctx-first** by convention.

Rules:

- Return type is the `T | Promise<T>` union — **never** `async` on the default impl.
- Defaults are hardcoded in the resolver body (policy no longer lives on opts).
- Customers override with `async resolveXxx()` for async work; `Promise<T>` is a subtype of the union, so TS accepts the override.
- **NEVER** use `resolveXxx` as a `@Step` id or a `@Step` handler method name. `resolveXxx` is exclusively for getter methods.

## `prepare-<group>` @Step — call resolver, write ctx

Each resolveXxx has a paired `@Step("prepare-<kebab>")` that calls it and writes the result to `ctx.<group>`. The body branches on `result instanceof Promise` to preserve the engine's sync fast path:

```ts
@Step("prepare-device-trust")
prepareDeviceTrust(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
  const result = this.resolveDeviceTrust(ctx);
  if (result instanceof Promise) {
    return result.then((r) => { ctx.deviceTrust = r; return undefined; });
  }
  ctx.deviceTrust = result;
  return undefined;
}
```

- Method name: `prepareXxx` (camelCase).
- @Step id: `prepare-<kebab-group>`.

## @Step return type — `T | Promise<T>` union

Default sync `@Step` bodies type the return as `T | Promise<T>` so customer subclasses can override with `async`:

```ts
initLogin(ctx): undefined | Promise<undefined> { return undefined; }            // sync default
selectMfaMethod(ctx): undefined | Promise<undefined> { ... }                    // sync default
```

The wf engine awaits **only when the actual return value is a Promise**. Adding `async` to a default impl forces every default call to allocate a Promise, defeating the framework's sync fast-path optimization.

### Pure extension-point stubs — `unknown | Promise<unknown>`

A small set of `@Step` bodies are **pure consumer extension points**: no-op /
placeholder defaults that exist only so a customer subclass can override them
with arbitrary behaviour. These type their return as `unknown | Promise<unknown>`
— NOT the narrow `undefined`/`void` the default body actually returns — so the
override is free to return anything (a form pause, an `HttpResponse`, a payload,
sync or async) without fighting the base signature:

```ts
@Step("extra-step")
@Public()
// oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
extraStep(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> { return undefined; }
```

This applies to `extra-step` and the four alt-cred stubs (`magic-link-request`,
`magic-link-send`, `magic-link-verified`, `passkey`). (`sso-callback` is NO
LONGER a stub — federated login is merged into the login workflow, so it carries
the real OAuth-callback exchange; see `AuthWorkflow.ssoCallback`.) It is the
**exception** to the `T | Promise<T>` rule above — use the precise `T` form for
every step whose default body carries real behaviour; reserve the `unknown` form
for these designated override seams.

**Lint note — the `oxlint-disable-next-line` directive above is required.**
`unknown | Promise<unknown>` collapses to `unknown` (the top type absorbs the
union), so the `correctness`-category rule `no-redundant-type-constituents`
flags it and the pre-commit `vp check --fix` hook would otherwise rewrite it
back to bare `unknown`, silently dropping the sync|async intent signal. The
per-line disable keeps the explicit union (TS still normalises the emitted
`.d.ts` type to `unknown`; the union is source-level documentation). Add the
same directive to any new extension-point stub. Do NOT disable the rule
workspace-wide in the root `vite.config.ts` — it catches real redundant unions
everywhere else.

## Step IDs

- **kebab-case**: `prepare-mfa`, `ensure-email`, `pincode-send`.
- The wf engine registers `@Step("id")` globally — duplicate ids silently overwrite. With a single concrete class owning every step body, collisions only matter when a customer subclass adds new ids; pick names that won't clash with the base class's inventory.
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
| `!ctx.otp?.verified` inside the MFA while-loop                                  | ❌ — keep per-step                                        | Sibling steps may flip it mid-iteration |

## `prepare-*` placement in the schema

All prepare-\* steps run AFTER `credentials` and the `{ break: !ctx.username }` gate (so resolvers can read `ctx.username` for user-specific overrides), but BEFORE any policy-using step.

**Exception — `credentials` runs BEFORE the username gate**, so it cannot rely on prepare-\*. It inline-calls `resolveAlternateCredentials(ctx)` + `resolveGuards(ctx)` (the two policies it needs for alt-action routing and `passwordInitial` detection). Later prepare-\* steps idempotently re-write the same values once username is set.

## Helpers stay strictly sync

Protected methods called from default @Step bodies stay sync-only — do NOT widen them to `T | Promise<T>`:

```ts
protected resolveRecoveryUrl(username: string | undefined, alt: ...): string { ... }
protected resolveRedirect(ctx): string | undefined { ... }
```

If a customer needs async logic in a helper, they override the **calling @Step**, not the helper. Widening helper return types would force `await` at default call sites and defeat the sync fast path.

`load*` methods (e.g. `loadActiveSessions`) stay async because they hit external stores — but they're **data fetchers**, not policy resolvers. Do NOT rename them to `resolveXxx`.

## DI scope — SINGLETON by default

`@Controller()` implies `@Injectable(true)` (SINGLETON). `AuthWorkflow` holds no per-event mutable state on `this` — per-event state lives on `ctx` + wooks composables — so one instance per app lifetime is correct. Don't add `@Injectable("FOR_EVENT")` to `AuthWorkflow` or its subclasses.

**Add `@Injectable("FOR_EVENT")` ONLY when**:

- The constructor reads request-scoped composables (e.g. `useHeaders()` in the ctor to pick a variant config).
- The class holds per-event state on instance properties.

moost@0.6.x does NOT inherit `@Injectable` across `extends`, so each subclass must re-apply its scope decorator if it needs one. Subclasses inheriting from a SINGLETON `AuthWorkflow` can drop `@Injectable` entirely — `@Controller()` provides the implicit SINGLETON.

## `@Public()` — per-method decision

`AuthWorkflow` itself is NOT `@Public()` at the class level — invite admin-phase @Step methods are arbac-evaluated (the admin needs the `invite` permission). Instead:

- The four **public** `@Workflow` bodies (`loginFlow`, `inviteFlow`, `recoveryFlow`, `signupFlow`) all carry `@Public()` so the wf adapter can dispatch start/resume on anonymous magic-link clicks, self-signups, and unauthenticated logins.
- The two **gated** `@Workflow` bodies (`changePasswordFlow`, `addMfaFlow`) do NOT carry `@Public()` — they (plus their `init-*` / `finish-*` steps) carry `@ArbacResource("auth.change-password" | "auth.add-mfa") @ArbacAction("self")`, so an anonymous request 401s and an unprivileged one 403s before the flow starts (the grant is the on/off switch — no opts flag). Every step of change-password is decorated too; add-mfa decorates its `init`/`finish` plus the manage steps (`prepare-locked-mfa-transports`, `manage-stepup-done`, `manage-menu`, `confirm-remove-mfa`) and relies on the gated init running first. See the docs-site "ARBAC Authorize — gating a whole workflow".
- Every @Step the engine may land on under anonymous auth carries per-step `@Public()` — login's entire step set, recovery's entire step set, signup's entire step set, and invite's accept-tail steps. Admin-phase @Step methods (`admin-form`, `infer-roles`, `build-user-extras`, `create-user`) deliberately omit `@Public()`. **Caveat for the gated flows:** add-mfa reuses login's enroll-trio AND MFA-challenge (step-up) steps, which ARE `@Public()` — but its gated `init-add-mfa` runs first, so entry is always authorized; the public reused steps are only reachable mid-flow once the gate has passed.

Pick the default per step by asking: **can an anonymous request legitimately land on this step?** If yes, `@Public()`. If no, leave it off and let arbac evaluate normally.

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
class MyAuth extends AuthWorkflow {
  constructor(
    opts: Partial<AuthWorkflowOpts>,
    users: UserService,
    auth: AuthCredential,
    consentStore: ConsentStore,
  ) {
    super(opts, users, auth, consentStore); // re-declared so TS emits design:paramtypes
  }

  protected resolveDeviceTrust(ctx: AuthWfCtx) {
    return { enabled: this.tenantWantsTrustedDevices(), optIn: true, skipsMfa: true };
  }

  protected async resolveSessionPolicy(ctx: AuthWfCtx) {
    return { concurrencyLimit: await this.tenantsDb.concurrencyLimitFor(ctx.username!) };
  }

  protected resolveAccept(ctx: AuthWfCtx) {
    // Only reached from invite.start accept phase — ctx.accept will be the
    // current resolved policy slot. Safe to assume invite-accept context.
    return {
      alreadyAcceptedRedirectUrl: this.opts.loginUrl,
      loginUrl: this.opts.loginUrl,
      showConfirmation: true,
      confirmationMessage: "Welcome to MyApp!",
    };
  }
}
```

Subclass MUST:

- Re-apply `@Inherit() @Controller()` (and `@Injectable("FOR_EVENT")` only if the ctor needs composables).
- Re-declare the constructor signature — TS emits fresh `design:paramtypes` metadata per class; without an explicit ctor, moost can't resolve DI.

## Adding a new policy group

1. Add an optional field on `AuthWfCtx`: `xxxxx?: { ... };`.
2. Add a protected resolver `resolveXxxxx(ctx)` in the `// ── Resolved policy surface ──` block. Return type: `NonNullable<AuthWfCtx["xxxxx"]> | Promise<NonNullable<AuthWfCtx["xxxxx"]>>`. Default body returns hardcoded values.
3. Add the `@Step("prepare-xxxxx")` method with the Promise-branched body (mirror an existing one).
4. Add `{ id: "prepare-xxxxx" }` to the relevant `@Workflow` schema(s), AFTER `credentials`/`!ctx.username` gate, BEFORE any policy-using step.
5. Schema conditions and step bodies read `ctx.xxxxx?.<flag>`.

## What NOT to do

- ❌ `async` keyword on default `@Step` bodies (forces Promise allocation; breaks fast path).
- ❌ `await this.resolveXxx(ctx)` in default @Step bodies (same problem).
- ❌ Reading `this.opts.<policy-group>.<flag>` (policy lives on resolvers, not opts).
- ❌ Adding policy flags back to `AuthWorkflowOpts`.
- ❌ Per-method `@Public()` when the enclosing @Workflow body is `@Public()` AND the @Step is unconditionally reachable only by that workflow — covered already. (The current style is to mark every reachable-anon step `@Public()` explicitly for grep-ability.)
- ❌ Duck-typed casts on wooks event-context objects.
- ❌ Repeating `!ctx.aborted` / `!!ctx.username` on every downstream step — use `{ break: ... }` gates.
- ❌ Renaming `loadActiveSessions`-style data fetchers to `resolveXxx` (data fetchers, not policy resolvers).
- ❌ Using `resolveXxx` as a `@Step` id or `@Step` handler method name.
- ❌ Widening helper return types (`resolveRecoveryUrl`, `resolveRedirect`) to `T | Promise<T>` — stay strictly sync; consumers needing async override the calling @Step.
- ❌ Branching on a "flow name" — `AuthWfCtx` has no such field. Discriminate via ctx-slot presence (`ctx.admin` / `ctx.accept` / `ctx.postReset` / `ctx.signup` / `ctx.changePassword` / `ctx.addMfa`; none ⇒ login).
- ❌ Passing the workflow id / channel as a second argument to `ConsentStore.getPendingConsents` — the signature is `(username)` only; the consent universe is user-scoped, not workflow-scoped.
- ❌ `ctx.foo = undefined` to clear an optional ctx field at the end of a @Step body. The wf state-token persistence layer JSON-schema-validates the serialized ctx and rejects `undefined` (allowed types: string / number / boolean / null / array / object). Use `delete ctx.foo` instead — drops the key from the payload cleanly. Bare-boolean / nullable-string fields can also assign `false` / `null` if a forward step relies on presence rather than reads the field directly.
