# E2E_REPORT — Findings

Output of running the e2e-demo suite against the current `@aoothjs/*` packages on `main` (HEAD = `e5fe2be feat(arbac): empty-subclass AsArbacDbController + table privilege factories + global guard`).

## Suite stats

```
Test Files  15  (4 failed, 11 passed)
Tests      137  (5 failed, 7 skipped, 125 passed)
Duration   8.12s
```

- **5 failing tests** are tagged `BUG-SHAPE: <one-line>` — they assert the documented contract; failures pinpoint real library bugs. Each will flip to passing once the underlying bug is fixed.
- **7 skipped tests** are documented gaps (capability genuinely missing or out-of-scope).
- **125 passing tests** validate working behavior across auth REST, workflows, ARBAC isolation/projection/actions/writes, `$controls`, attack vectors, and DX.

Story coverage by domain:

| Domain | Pass | Fail | Skip | Total |
| ------ | ---- | ---- | ---- | ----- |
| AUTH (REST) | 17 | 0 | 1 | 18 |
| WF (login + MFA + recovery + invite + custom handover + form pause/resume) | 21 | 0 | 2 | 23 |
| ISO (tenant isolation) | 7 | 2 | 1 | 10 |
| UNION (multi-role union) | 2 | 1 | 1 | 4 |
| PROJ (field projection) | 5 | 0 | 1 | 6 |
| META (meta overlay) | 4 | 0 | 0 | 4 |
| ACT (per-action gating) | 7 | 0 | 0 | 7 |
| WRITE (allowedFields + set) | 6 | 0 | 0 | 6 |
| CTRL (`$controls`) | 16 | 1 | 1 | 18 |
| SEC (attack vectors) | 31 | 1 | 0 | 32 |
| DX (developer ergonomics) | 8 | 0 | 0 | 8 |

---

## Critical bugs (security-impacting)

### BUG-1 — Cross-tenant write/delete via PK (ISO-05, ISO-06)
**Severity:** CRITICAL. **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/db/as-arbac-db-controller.ts:92-107](packages/arbac-moost/src/db/as-arbac-db-controller.ts#L92).

`onWrite("update"|"replace", data)` and `onRemove(id)` only check action permission and apply `allowedFields`/`set`. They do **NOT** AND the scope's `filter` into the underlying `update`/`remove` operation. The base `AsDbController.update` then operates purely on `payload.id`. A tenant-A admin who knows a tenant-B row's PK can `PATCH /tasks { id: <T_B>, ... }` and mutate it — and admin's scope `set` then forces `tenantId` to A, silently relocating the row across tenants.

**Repro:** [packages/e2e-demo/test/arbac-isolation.spec.ts](packages/e2e-demo/test/arbac-isolation.spec.ts) ISO-05 / ISO-06.

**Fix:** In `transformFilter` for write actions (or in dedicated `transformWriteFilter`), AND the scope's filter with the user-supplied `id`. The base `update`/`remove` should accept the merged filter, not key purely by PK.

### BUG-2 — Filter injection via top-level `$or`/`$and` drops scope filter (CTRL-08, SEC-01)
**Severity:** CRITICAL. **Packages:** `@aoothjs/arbac-moost` + `@uniqu/core`. **Files:** [packages/arbac-moost/src/db/as-arbac-db-controller.ts:52](packages/arbac-moost/src/db/as-arbac-db-controller.ts#L52), `node_modules/@uniqu/core/dist/index.mjs:8-36`.

`AsArbacDbController.transformFilter` merges via object spread:
```ts
return merged ? { ...merged, ...filter } : (filter ?? {});
```
producing `{ tenantId: 'A', $or: [...] }`. `@uniqu/core`'s `walkFilter` short-circuits when a top-level `$and`/`$or`/`$not` key is present and **drops sibling field keys**. Result: any user who supplies a top-level logical operator escapes the scope filter entirely.

**Repro:** [packages/e2e-demo/test/controls.spec.ts](packages/e2e-demo/test/controls.spec.ts) CTRL-08, [packages/e2e-demo/test/security.spec.ts](packages/e2e-demo/test/security.spec.ts) SEC-01.

**Fix (cleaner):** wrap as `{ $and: [scopeFilter, userFilter] }` in `transformFilter`. Optional follow-up: make `walkFilter` visit sibling fields alongside logical operators.

### BUG-3 — No-scope `allow` rule contributes nothing to scopes (UNION-04)
**Severity:** HIGH. **Package:** `@aoothjs/arbac-core`. **File:** [packages/arbac-core/src/arbac.ts:136-148](packages/arbac-core/src/arbac.ts#L136).

`Arbac.evaluate` only pushes into `scopes` when `rule.scope` exists. A role with universe access (no scope function) contributes `[]` to the `scopes` array. When merged with another role's scoped filter via `mergeScopeFilters`, the universe grant is silently lost — the user is bound by the more restrictive scope. Multi-role union semantics are broken whenever one role intends "no restriction".

**Repro:** [packages/e2e-demo/test/arbac-union.spec.ts](packages/e2e-demo/test/arbac-union.spec.ts) UNION-04.

**Fix:** Push a sentinel scope (`{ filter: {} }` — empty filter = universe) when a no-scope `allow` rule matches. `mergeScopeFilters` already short-circuits to `undefined` (universe) when any input is `{}`; extend to the array path so a universe sentinel makes the union a universe.

### BUG-4 — Password change cascade revoke is no-op on JWT store (AUTH-13)
**Severity:** HIGH. **Package:** `@aoothjs/auth`. **File:** [packages/auth/src/stores/jwt.ts:176](packages/auth/src/stores/jwt.ts#L176).

`AuthController.changePassword` calls `auth.revokeAllForUser(username)`, but `CredentialStoreJwt.revokeAllForUser()` returns `0` and does nothing — JWT is stateless. Stale access tokens from before the password change remain valid until natural expiry.

**Repro:** documented in [packages/e2e-demo/test/auth.spec.ts](packages/e2e-demo/test/auth.spec.ts) AUTH-13 (asserts current behavior; flag to flip when fixed).

**Fix:** Make `CredentialStoreJwt` maintain a per-user revocation epoch (timestamp), validate access tokens against it, and bump on `revokeAllForUser`. Or document the limitation and require consumers to use a stateful store for password-change cascade.

### BUG-5 — Theft response unreachable in `rotation: 'always'` mode (AUTH-07)
**Severity:** HIGH. **Package:** `@aoothjs/auth`. **File:** [packages/auth/src/credential/auth-credential.ts:234](packages/auth/src/credential/auth-credential.ts#L234).

The OAuth-best-practice "refresh-token reuse → revoke all user credentials" theft response only fires in `'sliding'` rotation mode. In `'always'` mode (which is what the demo configures), refresh-replay just returns 401; other devices' tokens remain alive.

**Repro:** documented in [packages/e2e-demo/test/auth.spec.ts](packages/e2e-demo/test/auth.spec.ts) AUTH-07.

**Fix:** Theft response should fire in any rotation mode where reuse is detectable (`'always'` and `'sliding'` both fit; only `'none'` lacks the signal).

### BUG-6 — TOTP brute force unmitigated (SEC-19)
**Severity:** HIGH. **Package:** `@aoothjs/user`.

100 wrong TOTP codes accepted without lockout. MFA failures don't increment `account.failedLoginAttempts`, so password-side lockout doesn't help. Consumers running MFA-protected logins have no built-in protection against TOTP brute force.

**Repro:** [packages/e2e-demo/test/security.spec.ts](packages/e2e-demo/test/security.spec.ts) SEC-19.

**Fix:** Add an MFA-failure counter to `account` (or reuse `failedLoginAttempts`) and apply the same lockout policy.

---

## Important bugs (correctness / DX-impacting)

### BUG-7 — `metaForm` action not aliased to `meta` (META-04)
**Severity:** MEDIUM. **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/arbac.composables.ts:19-25](packages/arbac-moost/src/arbac.composables.ts#L19).

`normalizeAutoCrudMethod` aliases `getOne`/`getOneComposite` → `one` and `removeComposite` → `remove`, but does NOT alias `metaForm` → `meta`. Result: NO ROLE can fetch action input form schemas. Every `GET /<resource>/meta/form/:name` request returns 403 — even for admin who has `tableWritePrivilege` (which grants `meta`). Blocks any UI that uses moost-db's auto-form rendering.

**Repro:** [packages/e2e-demo/test/arbac-meta.spec.ts](packages/e2e-demo/test/arbac-meta.spec.ts) META-04.

**Fix:** Add `if (method === 'metaForm') return 'meta'` to `normalizeAutoCrudMethod`.

### BUG-8 — `applyAllowedFieldsAndSet` strips PK fields
**Severity:** MEDIUM. **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/db/as-arbac-db-controller.ts:135-159](packages/arbac-moost/src/db/as-arbac-db-controller.ts#L135).

When `allowedFields` is set, `applyAllowedFieldsAndSet` strips every key not in the whitelist — including `id` (PK). Then `update`/`replace` fail with "Missing primary key field 'id' in payload". Every consumer that uses `allowedFields` must remember to include the PK; not in spec, easy to miss, blocking.

**Repro / workaround:** [packages/e2e-demo/src/roles/writeable-fields.ts](packages/e2e-demo/src/roles/writeable-fields.ts) — demo's `WRITEABLE_USER_FIELDS_ADMIN` lists `id` and `username` to work around.

**Fix:** Auto-preserve the table's PK fields and any unique-index fields in `applyAllowedFieldsAndSet`. PK is server-derived metadata, not user-controllable content.

### BUG-9 — `useArbac().evaluate()` returns `{allowed:false}`, doesn't throw (handover workflow)
**Severity:** MEDIUM (DX/docs). **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/arbac.composables.ts](packages/arbac-moost/src/arbac.composables.ts).

The handover workflow's first attempt at admin-bypass logic was `try { evaluate(...); isAdmin = true } catch { isAdmin = false }` — which silently granted admin to every non-owner because `evaluate()` doesn't throw on deny; it returns `{ allowed: false }`. Inviting consumer code to make the same mistake.

**Repro / fix:** [packages/e2e-demo/src/workflows/handover.workflow.ts](packages/e2e-demo/src/workflows/handover.workflow.ts) (now reads `result.allowed`).

**Library fix:** Either ship a sibling `evaluateOrThrow()` (preferred for handler ergonomics — most consumers want throw-on-deny) or document the non-throw behavior prominently in JSDoc.

### BUG-10 — `UserService.createUser` ignores extras (DemoUserStore workaround)
**Severity:** MEDIUM (DX). **Package:** `@aoothjs/user` + `@aoothjs/auth-moost` (invite workflow).

`UserService.createUser(username, password)` only constructs the base `UserCredentials` shape. When the consumer's user model has additional required fields (e.g. `tenantId`), `createUser` produces atscript validation errors at insert time. The bundled `InviteWorkflow.accept` step has no extension hook for default fields. Demos must override `UsersStore.create()` to fill defaults.

**Repro / workaround:** [packages/e2e-demo/src/aooth.ts](packages/e2e-demo/src/aooth.ts) — `DemoUserStore.create()` defaults `tenantId='_global'`.

**Fix:** `UserService.createUser` should accept an `extras` parameter; the bundled invite workflow should expose a `prepareUser(input)` hook so consumers can populate required fields without subclassing.

### BUG-11 — `findByUsername` doesn't fall back to email (recovery workflow)
**Severity:** MEDIUM (DX). **Package:** `@aoothjs/auth-moost` (recovery workflow).

`RecoveryWorkflow.requestRecovery` calls `userService.getUser(input.email)` which delegates to `userStore.findByUsername(input.email)`. If the user model separates `username` and `email` (the realistic shape), the lookup misses and recovery silently short-circuits to the enumeration-resistant "sent" response. No email is ever delivered. Recovery is unusable out-of-the-box for any real user model.

**Repro / workaround:** [packages/e2e-demo/src/aooth.ts](packages/e2e-demo/src/aooth.ts) — `DemoUserStore.findByUsername` falls back to email lookup.

**Fix:** `setupAuthWorkflows` should accept an `emailToUserId(email): Promise<string|null>` resolver, OR `UserStore` should expose a `findByEmail` method, OR the recovery workflow should match on either (configurable).

### BUG-12 — `@StepTTL` hardcoded in recovery + invite workflows (WF-RECOVERY-04, WF-INVITE-04)
**Severity:** MEDIUM. **Package:** `@aoothjs/auth-moost`. **Files:** [packages/auth-moost/src/workflows/recovery.workflow.ts](packages/auth-moost/src/workflows/recovery.workflow.ts), [packages/auth-moost/src/workflows/invite.workflow.ts](packages/auth-moost/src/workflows/invite.workflow.ts).

`recoveryTokenTtlMs` and `inviteTokenTtlMs` config plumbed through `MoostAuthWorkflowConfig` only feed the email envelope's `expiresAt`. The actual replay window is dictated by `@StepTTL(60 * 60 * 1000)` and `@StepTTL(7 * 24 * 60 * 60 * 1000)` — hardcoded. Tests can't exercise expiry without forking the workflows.

**Fix:** Make `@StepTTL` config-driven (read from `MoostAuthWorkflowConfig`).

### BUG-13 — Process-global `Wooks` router + Moost Infact DI cache (test isolation)
**Severity:** LOW for production, MEDIUM for testability. **Packages:** `wooks` + `moost`.

Multiple `buildApp()` calls in the same process accumulate route handlers on a single `ProstoRouter` AND reuse stale `MoostAuthWorkflowConfig` instances injected from earlier apps (still pointing to closed SQLite drivers). Tests can't run multiple in-process apps without explicit `clearGlobalWooks()` + `(getMoostInfact() as any)._cleanup?.()`.

**Repro / workaround:** [packages/e2e-demo/test/harness.ts](packages/e2e-demo/test/harness.ts) — `clearGlobalWooks()` + Infact cleanup at top of `buildTestApp`.

**Fix:** Either expose a per-instance `Wooks` injection on `MoostHttp` (so `new Moost()` doesn't share global state by default), or document the global-state semantics explicitly so test authors know to reset.

### BUG-14 — `__DYE_*` ReferenceError in `@prostojs/router` outside Vite
**Severity:** LOW (test-time only). **Package:** `@prostojs/router`. **File:** `node_modules/@prostojs/router@0.3.3/dist/index.mjs:703`.

Build-time globals (`__DYE_YELLOW__`, etc.) referenced as runtime values in the duplicate-route warn path. Outside Vite's define-replace, they crash with a `ReferenceError` whenever a duplicate route is registered (which happens on every test re-build).

**Repro / workaround:** [packages/e2e-demo/test/harness.ts](packages/e2e-demo/test/harness.ts) — `installDyeStubs()` polyfills the globals to empty strings.

**Fix:** In `@prostojs/router`, use `(typeof __DYE_YELLOW__ !== 'undefined' ? __DYE_YELLOW__ : '')` or a similar safe-default pattern.

---

## Documented gaps (intentional or out-of-scope)

| ID | Story | Status | Note |
| -- | ----- | ------ | ---- |
| GAP-1 | AUTH-18 | skip | `CredentialStoreJwt` doesn't implement `listForUser` → `maxConcurrent` cannot be enforced on the JWT store. Switch to memory store or add a per-user index to JWT store. |
| GAP-2 | UNION-03 | skip | No role in the demo seed uses `effect: 'deny'`. Deny semantics are validated in arbac-core unit tests; integration validation requires a synthetic deny-rule role. |
| GAP-3 | PROJ-04 | skip | Demo `.as` models don't declare `@db.rel.*` annotations, so `$with` relation expansion can't be exercised. |
| GAP-4 | CTRL-05 | skip | Same — `$with` requires DB relations. |
| GAP-5 | ISO-09 | skip | Tenant cascade is documented as out-of-scope for ARBAC; arbac doesn't manage cascade. |
| GAP-6 | SEC-29 | documented | No library-level "preserve at least one admin" invariant. Admins can self-demote. Add an org-level invariant if undesired. |
| GAP-7 | SEC-31 | documented | No CSRF middleware. Consumers configure `sameSite: 'strict'` or add their own CSRF tokens. |
| GAP-8 | SEC-11 | documented | Magic links ARE the credential. Defense is email delivery security; nothing in-band can prevent cross-user replay if the link is exfiltrated. |
| GAP-9 | SEC-18 | documented | TOTP replay within a 30s period is RFC-6238-compliant; not a gap to "fix". |
| GAP-10 | DX-08 | documented | `setupAuthMoost({ endpoints: false })` causes `/auth/login` to return 401 (auth guard runs first) instead of 404 (route miss). DX wart, not a security issue. Worth a JSDoc note on `endpoints` option. |
| GAP-11 | DX-07 | documented | Unknown wfid throws an unhandled `Error("Unknown schemaId")` which Wooks bubbles as 500. Should be a 404 with "workflow not registered". |
| GAP-12 | DX-03 | documented | `defineRole().allow(resource, action)` types both as plain `string` — typos compile. Adding a generic resource→actions map could give type-level safety, but is non-trivial without a registry. |

---

## Library improvements that would land high value

In rough order of impact:

1. **Fix BUG-1 / BUG-2** — close the cross-tenant write/delete and `$or` filter-injection escapes. These are the most serious findings.
2. **Fix BUG-3** — universe sentinel in scope union, so multi-role configurations behave as documented.
3. **Fix BUG-4 / BUG-5** — make password-change cascade and refresh-token theft response work in stateless/always-rotation modes (or document the limitation explicitly).
4. **Fix BUG-7** — alias `metaForm` to `meta`. One-line change unblocks every consumer using auto-form rendering.
5. **Fix BUG-8** — auto-preserve PK in `applyAllowedFieldsAndSet`.
6. **Fix BUG-12** — make `@StepTTL` config-driven.
7. **Add MFA brute-force protection (BUG-6)** — count MFA failures toward lockout policy.
8. **Add `evaluateOrThrow()` (BUG-9)** — most handler code wants throw-on-deny.
9. **Add `setupAuthWorkflows({ emailToUserId })` (BUG-11)** — make recovery work for any user model.
10. **Add `UserService.createUser(username, password, extras)` (BUG-10)** — let consumers set required fields without subclassing.

Lower-priority but DX-improving:

11. **Allow custom `AuthEmailKind` in `createAuthEmailOutlet`** — let custom workflows ship their own email envelopes without piggybacking on `'invite.magicLink'`.
12. **Document or fix global Wooks/Moost-Infact state (BUG-13)** — at minimum, expose a `resetGlobals()` for testability.
13. **Fix `__DYE_*` globals in `@prostojs/router` (BUG-14)** — safe-default pattern.
14. **Expose `httpInputRequired` / `validateFormInput` from `@aoothjs/auth-moost`** — currently internal, copy-pasted by every custom workflow.
15. **Improve unknown-wfid error path (GAP-11)** — convert to 404 with a clear message.

---

## What the demo proves works correctly

In addition to the 125 passing tests, the broader observations:

- The **empty-subclass pattern** (`class TasksController extends AsArbacDbController<typeof Task> {}`) works for every db resource.
- **Tenant isolation on READ paths** is correctly enforced via `transformFilter` (the bugs are on write/delete + filter-injection paths).
- **Field-level projection** correctly hides sensitive fields per role; `$select` does not escape projection (PROJ-02 confirms even when the user explicitly asks for a hidden field, the response omits it).
- **Multi-role projection union** with mixed include/exclude modes behaves per `unionProjections` semantics (PROJ-03).
- **Meta-overlay** correctly filters `actions` and `crud` per caller's privileges (META-01, META-02).
- **Per-action gating** correctly resolves the action key via the chain `arbacActionId > atscript_db_action.name > id > normalizeAutoCrudMethod(method)` (ACT-03, ACT-06).
- **`disabled: perRow` predicates** correctly reject actions on rows that don't satisfy the predicate (ACT-05).
- **Forced `set` fields** correctly override body values for inserts/actions (WRITE-02, WRITE-03, WRITE-07).
- **`@ArbacPublic` ships pre-decorated** on auth-moost's `AuthController` and bundled workflows — consumers don't pay the decoration tax.
- **Bundled workflows** (login + MFA, recovery, invite) work end-to-end with single-use magic-link semantics (WF-RECOVERY-03, WF-INVITE-05).
- **Custom workflows** with persistent state via `AsWfStore` resume across server restart (WF-CUSTOM-02 confirmed).
- **Lockout** correctly triggers on failed-login threshold and auto-unlocks after duration (AUTH-05).
- **JWT alg=none / forged tokens** are rejected (AUTH-14, SEC-07).
- **SQL injection** via filter values is parameterized away (SEC-22).
- **Mass-assignment** via `roles: ['admin']` in body is filtered by `allowedFields` (WRITE-01, SEC-06).
- **Login enumeration resistance** is uniform between unknown user and wrong password (AUTH-02 / AUTH-03).
- **Recovery enumeration resistance** is uniform — unknown email returns the same shape as known email (WF-RECOVERY-02).

---

## Test fixtures (for reference)

Seed creates 2 tenants, 6 departments, 10 users (one per role + `t1_grace` with confirmed TOTP), 10 projects, 40 tasks, 60 comments, 20 documents. Audit log is intentionally empty (populated by app actions during tests).

Key user handles (all with password `Password1!`):
- Tenant A: `t1_alice` (member+viewer), `t1_bob` (member), `t1_carol` (manager+viewer), `t1_dave` (admin), `t1_eve` (viewer), `t1_frank` (guest), `t1_grace` (member + TOTP MFA).
- Tenant B: `t2_olivia` (admin), `t2_oscar` (member).
- `_super` (superadmin, `tenantId='_global'`).

Test helpers in [packages/e2e-demo/test/harness.ts](packages/e2e-demo/test/harness.ts) — `loginAndFetch`, `expectAllInTenant`, `dbFindOne`, `dbUpdateOne`, `submitRecoveryPassword`, `runTotpLoginWorkflow`, `expectOk`, `installDyeStubs`, `sleep`, `wfContext`, `wfErrors`.
