# E2E_REPORT — Findings

Output of running the e2e-demo suite against the current `@aoothjs/*` packages on `main` (HEAD = `e5fe2be feat(arbac): empty-subclass AsArbacDbController + table privilege factories + global guard`).

## Suite stats

All 12 documented bugs are fixed. Suite is fully green; the 4 remaining skips are documented out-of-scope gaps (see GAP-\* table near the end).

```
e2e-demo:                Test Files  16  (16 passed)
                         Tests      130  (0 failed, 4 skipped, 126 passed)

@aoothjs/arbac:          Test Files   8  (8 passed)
                         Tests      126  (126 passed)

@aoothjs/arbac-moost:    Test Files  12  (12 passed)
                         Tests       89  (89 passed)

@aoothjs/auth:           Test Files   9  (9 passed)
                         Tests      117  (117 passed)

@aoothjs/user:           Test Files  11  (11 passed)
                         Tests      179  (179 passed)
```

- **4 skipped tests** are documented gaps (capability genuinely missing or out-of-scope).
- **126 passing tests** in e2e-demo validate working behavior across auth REST, workflows, ARBAC isolation/projection/actions/writes/control-gating, attack vectors, and DX. The unit suites add another 511 passing tests covering helpers and integration hooks.

Story coverage by domain:

| Domain                                                                     | Pass | Fail | Skip | Total |
| -------------------------------------------------------------------------- | ---- | ---- | ---- | ----- |
| AUTH (REST)                                                                | 17   | 0    | 1    | 18    |
| WF (login + MFA + recovery + invite + custom handover + form pause/resume) | 23   | 0    | 0    | 23    |
| ISO (tenant isolation)                                                     | 9    | 0    | 1    | 10    |
| UNION (multi-role union)                                                   | 3    | 0    | 1    | 4     |
| PROJ (field projection)                                                    | 5    | 0    | 1    | 6     |
| META (meta overlay)                                                        | 4    | 0    | 0    | 4     |
| ACT (per-action gating)                                                    | 7    | 0    | 0    | 7     |
| WRITE (allowedFields + set)                                                | 6    | 0    | 0    | 6     |
| CTRL (`$controls` scope preservation)                                      | 9    | 0    | 0    | 9     |
| CTRL-EX (per-control gating — NEW feature)                                 | 8    | 0    | 0    | 8     |
| SEC (attack vectors)                                                       | 27   | 0    | 0    | 27    |
| DX (developer ergonomics)                                                  | 8    | 0    | 0    | 8     |

CTRL/SEC counts shrank in the e2e-demo refocus pass: stories that test other repos' concerns (moost-db / @uniqu/core operator semantics + pagination shape; @wooksjs body-parser DoS; @atscript/db SQL parameterization; render-side XSS; CSRF middleware) were removed because they belong in those repos' suites. CTRL-EX-\* is a new story group covering the per-control gating feature added in Phase 3 — see the Capabilities section.

---

## Capabilities added (post-initial-audit)

### CAP-1 — Per-control scope gating (`ArbacDbScope.controls`)

A new field on `ArbacDbScope` lets a role's scope deny or whitelist specific Uniquery `$controls`:

```ts
interface ArbacDbScope {
  filter?: TScopeFilter;
  projection?: TProjection;
  set?: Record<string, unknown>;
  allowedFields?: string[];
  controls?: Record<string, ControlGate>; // NEW
}

type ControlGate = boolean | readonly string[];
// false: deny entirely (403); string[]: whitelist values; true / absent: allow
```

Multi-role union semantics match the rest of arbac (additive — silence in any role grants full allow). Currently whitelisted on `$with` and `$groupBy`; boolean-only for the rest.

**Demo wiring:** viewer denies `{$with: false, $groupBy: false, $having: false}`; member denies `{$groupBy: false, $having: false}` (silence on `$with` → allowed). Manager / admin / superadmin are silent on all controls (full allow).

**Repro:** [packages/e2e-demo/test/controls-policy.spec.ts](packages/e2e-demo/test/controls-policy.spec.ts) — CTRL-EX-01..08 (all 8 active and passing on `@atscript/moost-db@0.1.78`).

**Implementation:** [packages/arbac/src/scope/controls.ts](packages/arbac/src/scope/controls.ts) (`unionControlsPolicy` helper), [packages/arbac-moost/src/db/as-arbac-db-controller.ts](packages/arbac-moost/src/db/as-arbac-db-controller.ts) (`validateControls` override + `enforceControlsPolicy` + `extractUsedControlValues`).

### CAP-2 — `@db.rel.FK` foreign keys + nav props on demo models

Phase 2 added FK chain-ref types on every cross-table reference (`tenantId`, `departmentId`, `projectId`, `taskId`). Better-sqlite3's `PRAGMA foreign_keys = ON` is unconditional in atscript-db's adapter, so the seed insert order is now FK-validated at runtime. A synthetic `_global` tenant row exists to satisfy the `_super` user's `tenantId='_global'` sentinel under FK enforcement.

Nav props (`@db.rel.to` on Comment.task, `@db.rel.from` on Task.comments) landed once `@atscript/moost-db@0.1.78` shipped a generic `TableController<Table extends AtscriptDbTable<...>>` that accepts tables with non-empty `NavType`. CTRL-05 ($with=comments expansion) is now active.

---

## Upstream quirks (resolved by `@atscript/moost-db@0.1.78`)

### QUIRK-1 — moost-db's `$groupBy` short-circuit bypassed `validateControls` _(FIXED upstream)_

In 0.1.75–0.1.76 `query(url)` dispatched to `aggregate(...)` whenever `controls.$groupBy?.length > 0`, BEFORE `validateParsed` (which calls `validateControls`). Per-control gating couldn't fire on aggregate paths.

Fix landed in `@atscript/moost-db@0.1.78` (commit `3f9ac93`): `validateParsed` + `checkGates` now run first, then the aggregate dispatch happens. CTRL-EX-02 / CTRL-EX-05 (viewer / multi-role union both deny `$groupBy`) are now active and passing.

### QUIRK-2 — moost-db's `@TableController` variance issue with nav props _(FIXED upstream)_

In 0.1.75–0.1.76, `@TableController(table)` accepted bare `AtscriptDbTable` only — adding `@db.rel.to` / `@db.rel.from` annotations to `.as` models broke type inference because `AtscriptDbTable<T-with-nav>` isn't assignable to bare `AtscriptDbTable`.

Fix in `@atscript/moost-db@0.1.78`: `TableController` is now generic over `Table extends AtscriptDbTable<any, any, any, any, any, any, any>`. Demo's Task → Comment nav prop is declared and CTRL-05 verifies `$with=comments` expansion.

---

## Critical bugs (security-impacting)

### BUG-1 — Cross-tenant write/delete via PK (ISO-05, ISO-06)

**Severity:** CRITICAL. **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/db/as-arbac-db-controller.ts:92-107](packages/arbac-moost/src/db/as-arbac-db-controller.ts#L92).

`onWrite("update"|"replace", data)` and `onRemove(id)` only check action permission and apply `allowedFields`/`set`. They do **NOT** AND the scope's `filter` into the underlying `update`/`remove` operation. The base `AsDbController.update` then operates purely on `payload.id`. A tenant-A admin who knows a tenant-B row's PK can `PATCH /tasks { id: <T_B>, ... }` and mutate it — and admin's scope `set` then forces `tenantId` to A, silently relocating the row across tenants.

**Repro:** [packages/e2e-demo/test/arbac-isolation.spec.ts](packages/e2e-demo/test/arbac-isolation.spec.ts) ISO-05 / ISO-06.

**Fix:** In `transformFilter` for write actions (or in dedicated `transformWriteFilter`), AND the scope's filter with the user-supplied `id`. The base `update`/`remove` should accept the merged filter, not key purely by PK.

**Status:** ✅ FIXED — `onWrite` (update/replace) and `onRemove` now pre-fetch via `table.count({ filter: { $and: [resolveIdFilter(id), scopeFilter] } })` and throw 404 when the targeted row is out of scope. ISO-05 and ISO-06 flipped from BUG-SHAPE to passing.

### BUG-2 — Filter injection via top-level `$or`/`$and` drops scope filter (CTRL-08, SEC-01)

**Severity:** CRITICAL. **Packages:** `@aoothjs/arbac-moost` + `@uniqu/core`. **Files:** [packages/arbac-moost/src/db/as-arbac-db-controller.ts:52](packages/arbac-moost/src/db/as-arbac-db-controller.ts#L52), `node_modules/@uniqu/core/dist/index.mjs:8-36`.

`AsArbacDbController.transformFilter` merges via object spread:

```ts
return merged ? { ...merged, ...filter } : (filter ?? {});
```

producing `{ tenantId: 'A', $or: [...] }`. `@uniqu/core`'s `walkFilter` short-circuits when a top-level `$and`/`$or`/`$not` key is present and **drops sibling field keys**. Result: any user who supplies a top-level logical operator escapes the scope filter entirely.

**Repro:** [packages/e2e-demo/test/controls.spec.ts](packages/e2e-demo/test/controls.spec.ts) CTRL-08, [packages/e2e-demo/test/security.spec.ts](packages/e2e-demo/test/security.spec.ts) SEC-01.

**Fix (cleaner):** wrap as `{ $and: [scopeFilter, userFilter] }` in `transformFilter`. Optional follow-up: make `walkFilter` visit sibling fields alongside logical operators.

**Status:** ✅ FIXED — `transformFilter` now wraps scope and user filters as `{ $and: [scopeFilter, userFilter] }` rather than spreading. CTRL-08 and SEC-01 flipped from BUG-SHAPE to passing.

### BUG-3 — No-scope `allow` rule contributes nothing to scopes (UNION-04)

**Severity:** HIGH. **Package:** `@aoothjs/arbac-core`. **File:** [packages/arbac-core/src/arbac.ts:136-148](packages/arbac-core/src/arbac.ts#L136).

`Arbac.evaluate` only pushes into `scopes` when `rule.scope` exists. A role with universe access (no scope function) contributes `[]` to the `scopes` array. When merged with another role's scoped filter via `mergeScopeFilters`, the universe grant is silently lost — the user is bound by the more restrictive scope. Multi-role union semantics are broken whenever one role intends "no restriction".

**Repro:** [packages/e2e-demo/test/arbac-union.spec.ts](packages/e2e-demo/test/arbac-union.spec.ts) UNION-04.

**Fix:** Push a sentinel scope (`{ filter: {} }` — empty filter = universe) when a no-scope `allow` rule matches. `mergeScopeFilters` already short-circuits to `undefined` (universe) when any input is `{}`; extend to the array path so a universe sentinel makes the union a universe.

**Status:** ✅ FIXED — `Arbac.evaluate` now pushes `{}` (universe sentinel) into `scopes` when a matching `allow` rule has no `scope` function, so `mergeScopeFilters` short-circuits to universe under multi-role union. UNION-04 flipped from BUG-SHAPE to passing.

### BUG-4 — Password change cascade revoke is no-op on JWT store (AUTH-13)

**Severity:** HIGH. **Package:** `@aoothjs/auth`. **File:** [packages/auth/src/stores/jwt.ts:176](packages/auth/src/stores/jwt.ts#L176).

`AuthController.changePassword` calls `auth.revokeAllForUser(username)`, but `CredentialStoreJwt.revokeAllForUser()` returns `0` and does nothing — JWT is stateless. Stale access tokens from before the password change remain valid until natural expiry.

**Repro:** documented in [packages/e2e-demo/test/auth.spec.ts](packages/e2e-demo/test/auth.spec.ts) AUTH-13 (asserts current behavior; flag to flip when fixed).

**Fix:** Make `CredentialStoreJwt` maintain a per-user revocation epoch (timestamp), validate access tokens against it, and bump on `revokeAllForUser`. Or document the limitation and require consumers to use a stateful store for password-change cascade.

**Status:** ✅ FIXED — `CredentialStoreJwt` now keeps an in-memory `Map<username, epochMs>`. `revokeAllForUser` sets the epoch to `clock.now() + 1` and returns `1`; `retrieve`/`consume` reject any token whose mirrored `iatMs` is `< epoch`. AUTH-13 flipped from BUG-SHAPE to a strict 401-on-prior-tokens assertion. Limitation: the map is in-memory only — a server restart resets it, so tokens minted before the restart re-validate until natural expiry. Production deployments needing durability should back the epoch map with an external store (Redis / DB) via a custom store wrapper.

### BUG-5 — Theft response unreachable in `rotation: 'always'` mode (AUTH-07)

**Severity:** HIGH. **Package:** `@aoothjs/auth`. **File:** [packages/auth/src/credential/auth-credential.ts:234](packages/auth/src/credential/auth-credential.ts#L234).

The OAuth-best-practice "refresh-token reuse → revoke all user credentials" theft response only fires in `'sliding'` rotation mode. In `'always'` mode (which is what the demo configures), refresh-replay just returns 401; other devices' tokens remain alive.

**Repro:** documented in [packages/e2e-demo/test/auth.spec.ts](packages/e2e-demo/test/auth.spec.ts) AUTH-07.

**Fix:** Theft response should fire in any rotation mode where reuse is detectable (`'always'` and `'sliding'` both fit; only `'none'` lacks the signal).

**Status:** ✅ FIXED — `AuthCredential` now keeps an in-memory `Map<refreshToken, {userId, exp}>` of consumed refresh tokens. The refresh path checks the map when `store.retrieve` returns null and `rotation !== 'none'`; on a hit it fires `onRotationReuse`, calls `revokeAllForUser`, and throws `REFRESH_REUSE_DETECTED`. Works uniformly across stateful (memory) and stateless (JWT, Encapsulated) stores — the JWT denylist hit on `retrieve` no longer swallows the reuse signal. AUTH-07 now asserts that sibling-device tokens become invalid (401) after replay; both `auth-credential.spec.ts` "rotation 'always'" and the cross-store integration spec assert `REFRESH_REUSE_DETECTED` instead of `INVALID_TOKEN`. Limitation: the consumed-refresh map is in-memory — a server restart resets it, so a refresh token replayed across a restart degrades to plain `INVALID_TOKEN` without theft cascade.

### BUG-6 — TOTP brute force unmitigated (SEC-19)

**Severity:** HIGH. **Package:** `@aoothjs/user`.

100 wrong TOTP codes accepted without lockout. MFA failures don't increment `account.failedLoginAttempts`, so password-side lockout doesn't help. Consumers running MFA-protected logins have no built-in protection against TOTP brute force.

**Repro:** [packages/e2e-demo/test/security.spec.ts](packages/e2e-demo/test/security.spec.ts) SEC-19.

**Fix:** Add an MFA-failure counter to `account` (or reuse `failedLoginAttempts`) and apply the same lockout policy.

**Status:** ✅ FIXED — **Option A (shared counter).** `UserService.verifyMfa(username, code, totpConfig?)` is the new MFA verify entry point. It checks lockout first (auto-unlocks expired locks), verifies the user's confirmed `totp` method, increments `account.failedLoginAttempts` on a wrong code, and applies the same `lockout` policy that already guards `login`. On success it resets the counter to 0. `LoginWorkflow.mfa` was switched from the bare `verifyTotpCode` helper to `users.verifyMfa(...)` and translates `LOCKED` / `MFA_INVALID(lockEnds)` to HTTP 423. Sharing the counter across both factors keeps a single threshold to tune and closes the brute-force window a separate counter would otherwise leave open: an attacker who knows the password but not the TOTP gets exactly `lockout.threshold` total tries across BOTH factors, not `2 * threshold`. SEC-19 now asserts that 3 wrong codes (the configured threshold) trip a 423 lock and a follow-up `/auth/login` also returns 423 until the lock expires.

---

## Important bugs (correctness / DX-impacting)

### BUG-7 — `metaForm` action not aliased to `meta` (META-04)

**Severity:** MEDIUM. **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/arbac.composables.ts:19-25](packages/arbac-moost/src/arbac.composables.ts#L19).

`literal method name passthrough` aliases `getOne`/`getOneComposite` → `one` and `removeComposite` → `remove`, but does NOT alias `metaForm` → `meta`. Result: NO ROLE can fetch action input form schemas. Every `GET /<resource>/meta/form/:name` request returns 403 — even for admin who has `allowTableWrite` (which grants `meta`). Blocks any UI that uses moost-db's auto-form rendering.

**Repro:** [packages/e2e-demo/test/arbac-meta.spec.ts](packages/e2e-demo/test/arbac-meta.spec.ts) META-04.

**Fix:** Add `if (method === 'metaForm') return 'meta'` to `literal method name passthrough`.

**Status:** ✅ FIXED — alias added; admin and viewer (both holding `tasks.meta`) now get identical form schemas via `GET /tasks/meta/form/:name`.

### BUG-8 — `applyAllowedFieldsAndSet` strips PK fields

**Severity:** MEDIUM. **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/db/as-arbac-db-controller.ts:135-159](packages/arbac-moost/src/db/as-arbac-db-controller.ts#L135).

When `allowedFields` is set, `applyAllowedFieldsAndSet` strips every key not in the whitelist — including `id` (PK). Then `update`/`replace` fail with "Missing primary key field 'id' in payload". Every consumer that uses `allowedFields` must remember to include the PK; not in spec, easy to miss, blocking.

**Repro / workaround:** [packages/e2e-demo/src/roles/writeable-fields.ts](packages/e2e-demo/src/roles/writeable-fields.ts) — demo's `WRITEABLE_USER_FIELDS_ADMIN` lists `id` and `username` to work around.

**Fix:** Auto-preserve the table's PK fields and any unique-index fields in `applyAllowedFieldsAndSet`. PK is server-derived metadata, not user-controllable content.

**Status:** ✅ FIXED — `applyAllowedFieldsAndSet` now auto-preserves table PK fields, so consumers don't need to whitelist `id`. Demo's `WRITEABLE_USER_FIELDS_ADMIN` no longer includes `id`.

### BUG-9 — `useArbac().evaluate()` returns `{allowed:false}`, doesn't throw (handover workflow)

**Severity:** MEDIUM (DX/docs). **Package:** `@aoothjs/arbac-moost`. **File:** [packages/arbac-moost/src/arbac.composables.ts](packages/arbac-moost/src/arbac.composables.ts).

The handover workflow's first attempt at admin-bypass logic was `try { evaluate(...); isAdmin = true } catch { isAdmin = false }` — which silently granted admin to every non-owner because `evaluate()` doesn't throw on deny; it returns `{ allowed: false }`. Inviting consumer code to make the same mistake.

**Repro / fix:** [packages/e2e-demo/src/workflows/handover.workflow.ts](packages/e2e-demo/src/workflows/handover.workflow.ts) (now reads `result.allowed`).

**Library fix:** Either ship a sibling `evaluateOrThrow()` (preferred for handler ergonomics — most consumers want throw-on-deny) or document the non-throw behavior prominently in JSDoc.

**Status:** ✅ FIXED — added `useArbac().evaluateOrThrow(opts)` that throws `HttpError(403, 'Forbidden: <resource>/<action>')` on deny and returns `{ allowed: true, scopes, userId }` on allow. Demo handover workflow simplified to drop the foot-gun try/catch (kept on `evaluate()` since the owner-OR-admin check needs to inspect `allowed`).

### BUG-10 — `UserService.createUser` ignores extras (DemoUserStore workaround)

**Severity:** MEDIUM (DX). **Package:** `@aoothjs/user` + `@aoothjs/auth-moost` (invite workflow).

`UserService.createUser(username, password)` only constructs the base `UserCredentials` shape. When the consumer's user model has additional required fields (e.g. `tenantId`), `createUser` produces atscript validation errors at insert time. The bundled `InviteWorkflow.accept` step has no extension hook for default fields. Demos must override `UsersStore.create()` to fill defaults.

**Repro / workaround:** [packages/e2e-demo/src/aooth.ts](packages/e2e-demo/src/aooth.ts) — `DemoUserStore.create()` defaults `tenantId='_global'`.

**Fix:** `UserService.createUser` should accept an `extras` parameter; the bundled invite workflow should expose a `prepareUser(input)` hook so consumers can populate required fields without subclassing.

**Status:** ✅ FIXED — `UserService.createUser(username, password?, extras?)` now accepts an optional `Partial<T>` of extras merged AFTER the base `UserCredentials` shape (callers can populate required custom fields and override base defaults like `id`). `setupAuthWorkflows({ prepareUser })` exposes a new hook on `MoostAuthWorkflowConfig`; `InviteWorkflow.accept` calls it with `{ email, roles?, parsedRoles[] }` and forwards the returned record as `extras`. Demo migrated: `app.ts` wires `prepareUser: () => ({ tenantId: "_global" })`; the `DemoUserStore.create()` override stays as a fallback for non-invite paths (seeders / admin scripts) and continues to handle the structurally-required `id: ""` strip + `roles[]`/`email` defaults.

### BUG-11 — `findByUsername` doesn't fall back to email (recovery workflow)

**Severity:** MEDIUM (DX). **Package:** `@aoothjs/auth-moost` (recovery workflow).

`RecoveryWorkflow.requestRecovery` calls `userService.getUser(input.email)` which delegates to `userStore.findByUsername(input.email)`. If the user model separates `username` and `email` (the realistic shape), the lookup misses and recovery silently short-circuits to the enumeration-resistant "sent" response. No email is ever delivered. Recovery is unusable out-of-the-box for any real user model.

**Repro / workaround:** [packages/e2e-demo/src/aooth.ts](packages/e2e-demo/src/aooth.ts) — `DemoUserStore.findByUsername` falls back to email lookup.

**Fix:** `setupAuthWorkflows` should accept an `emailToUserId(email): Promise<string|null>` resolver, OR `UserStore` should expose a `findByEmail` method, OR the recovery workflow should match on either (configurable).

**Status:** ✅ FIXED — `setupAuthWorkflows({ emailToUserId })` resolver added to `AuthWorkflowsOptions`. `RecoveryWorkflow.requestRecovery` now resolves the email through it (when configured) before calling `userService.getUser(userId)`. When no resolver is set, it falls back to the previous behavior (treating the email as the username) for back-compat. Returning `null` from the resolver short-circuits to the enumeration-resistant "sent" response. Demo wires `emailToUserId: async (email) => (await userStore.findByUsername(email))?.username ?? null`; the `DemoUserStore.findByUsername` fallback stays as defensive cover for non-recovery callers (arbacUserReader, programmatic lookups). New unit tests in `workflows.recovery.spec.ts` cover both resolver-success and resolver-null paths.

### BUG-12 — `@StepTTL` hardcoded in recovery + invite workflows (WF-RECOVERY-04, WF-INVITE-04)

**Severity:** MEDIUM. **Package:** `@aoothjs/auth-moost`. **Files:** [packages/auth-moost/src/workflows/recovery.workflow.ts](packages/auth-moost/src/workflows/recovery.workflow.ts), [packages/auth-moost/src/workflows/invite.workflow.ts](packages/auth-moost/src/workflows/invite.workflow.ts).

`recoveryTokenTtlMs` and `inviteTokenTtlMs` config plumbed through `MoostAuthWorkflowConfig` only feed the email envelope's `expiresAt`. The actual replay window is dictated by `@StepTTL(60 * 60 * 1000)` and `@StepTTL(7 * 24 * 60 * 60 * 1000)` — hardcoded. Tests can't exercise expiry without forking the workflows.

**Fix:** Make `@StepTTL` config-driven (read from `MoostAuthWorkflowConfig`).

**Status:** ✅ FIXED — dropped `@StepTTL(...)` from both `RecoveryWorkflow.sendLink` and `InviteWorkflow.sendLink` and instead attach `expires: Date.now() + ttl` directly to the `outletEmail(...)` result at runtime, reading the TTL from `MoostAuthWorkflowConfig.config.{recoveryTokenTtlMs,inviteTokenTtlMs}`. The decorator approach was infeasible (the `@StepTTL(n)` decorator from `@moostjs/event-wf` only accepts a `number` literal evaluated at class-definition time — there is no function-form support and no runtime `setTTL` API in 0.6.9). The runtime `expires` field on the step's `WfOutletSignal` is honored end-to-end: `WooksWf` propagates it into `strategy.persist(state, { ttl })`, which sets `expiresAt` on the `WfStateStore` row (both `WfStateStoreMemory` and `AsWfStore` honor it). `recoveryTokenTtlMs` / `inviteTokenTtlMs` config (and the `RECOVERY_TTL_MS` / `INVITE_TTL_MS` env vars in the demo) now drive the actual replay window, not just the email envelope. WF-RECOVERY-04 and WF-INVITE-04 are unskipped and pass.

### BUG-13 — Process-global `Wooks` router + Moost Infact DI cache (test isolation) — _by design_

**Severity:** N/A (clarified as intended usage). **Packages:** `wooks` + `moost`.

Multiple `buildApp()` calls in the same process accumulate route handlers on a single `ProstoRouter` AND reuse Moost's process-global Infact DI registry. This is **intentional**: the global registry is what gives `useArbac()`, `useControllerContext()`, and the rest of the composables their zero-config ergonomics in user code.

**Proper test usage:** call `clearGlobalWooks()` and `(getMoostInfact() as any)._cleanup?.()` between in-process app boots. The e2e harness ([packages/e2e-demo/test/harness.ts](packages/e2e-demo/test/harness.ts)) does this once at the top of `buildTestApp`. Not a bug — documented here for any future test author who hits the same shape.

### BUG-14 — `__DYE_*` ReferenceError in `@prostojs/router` outside Vite

**Severity:** LOW (test-time only). **Package:** `@prostojs/router`. **Was at:** `0.3.3/dist/index.mjs:703`.

Build-time globals (`__DYE_YELLOW__`, etc.) were referenced as runtime values in the duplicate-route warn path. Outside Vite's define-replace, they crashed with a `ReferenceError` whenever a duplicate route was registered.

**Status:** ✅ FIXED upstream in `@prostojs/router@0.3.4` (transitively bumped via `wooks@0.7.12` / `moost@0.6.10`). The dist no longer references `__DYE_*` at runtime. The `installDyeStubs()` workaround was removed from the harness; all 16 spec files now boot Moost cleanly.

---

## Documented gaps (intentional or out-of-scope)

| ID     | Story    | Status     | Note                                                                                                                                                                                            |
| ------ | -------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GAP-1  | AUTH-18  | skip       | `CredentialStoreJwt` doesn't implement `listForUser` → `maxConcurrent` cannot be enforced on the JWT store. Switch to memory store or add a per-user index to JWT store.                        |
| GAP-2  | UNION-03 | skip       | No role in the demo seed uses `effect: 'deny'`. Deny semantics are validated in arbac-core unit tests; integration validation requires a synthetic deny-rule role.                              |
| GAP-3  | PROJ-04  | skip       | Demo `.as` models don't declare `@db.rel.*` annotations, so `$with` relation expansion can't be exercised.                                                                                      |
| GAP-4  | CTRL-05  | skip       | Same — `$with` requires DB relations.                                                                                                                                                           |
| GAP-5  | ISO-09   | skip       | Tenant cascade is documented as out-of-scope for ARBAC; arbac doesn't manage cascade.                                                                                                           |
| GAP-6  | SEC-29   | documented | No library-level "preserve at least one admin" invariant. Admins can self-demote. Add an org-level invariant if undesired.                                                                      |
| GAP-8  | SEC-11   | documented | Magic links ARE the credential. Defense is email delivery security; nothing in-band can prevent cross-user replay if the link is exfiltrated.                                                   |
| GAP-9  | SEC-18   | documented | TOTP replay within a 30s period is RFC-6238-compliant; not a gap to "fix".                                                                                                                      |
| GAP-10 | DX-08    | documented | Skipping `registerControllers(AuthController)` causes `/auth/login` to return 401 (auth guard runs first) instead of 404 (route miss). DX wart, not a security issue.                           |
| GAP-11 | DX-07    | documented | Unknown wfid throws an unhandled `Error("Unknown schemaId")` which Wooks bubbles as 500. Should be a 404 with "workflow not registered".                                                        |
| GAP-12 | DX-03    | documented | `defineRole().allow(resource, action)` types both as plain `string` — typos compile. Adding a generic resource→actions map could give type-level safety, but is non-trivial without a registry. |

---

## Library improvements that would land high value

In rough order of impact:

All 12 documented aoothjs bugs are fixed: BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12. BUG-13 is reclassified as intended usage (the global Wooks/Moost-Infact registry powers the composables; tests reset it explicitly). BUG-14 was fixed upstream in `@prostojs/router@0.3.4`; the harness workaround is removed.

Lower-priority but DX-improving:

10. **Allow custom `AuthEmailKind` in `createAuthEmailOutlet`** — let custom workflows ship their own email envelopes without piggybacking on `'invite.magicLink'`.
11. **Expose `httpInputRequired` / `validateFormInput` from `@aoothjs/auth-moost`** — currently internal, copy-pasted by every custom workflow.
12. **Improve unknown-wfid error path (GAP-11)** — convert to 404 with a clear message.

---

## What the demo proves works correctly

In addition to the 125 passing tests, the broader observations:

- The **empty-subclass pattern** (`class TasksController extends AsArbacDbController<typeof Task> {}`) works for every db resource.
- **Tenant isolation on READ paths** is correctly enforced via `transformFilter` (the bugs are on write/delete + filter-injection paths).
- **Field-level projection** correctly hides sensitive fields per role; `$select` does not escape projection (PROJ-02 confirms even when the user explicitly asks for a hidden field, the response omits it).
- **Multi-role projection union** with mixed include/exclude modes behaves per `unionProjections` semantics (PROJ-03).
- **Meta-overlay** correctly filters `actions` and `crud` per caller's privileges (META-01, META-02).
- **Per-action gating** correctly resolves the action key via the chain `arbacActionId > atscript_db_action.name > id > literal method name passthrough(method)` (ACT-03, ACT-06).
- **`disabled: perRow` predicates** correctly reject actions on rows that don't satisfy the predicate (ACT-05).
- **Forced `set` fields** correctly override body values for inserts/actions (WRITE-02, WRITE-03, WRITE-07).
- **`@Public()` (combined auth + arbac bypass) ships pre-decorated** on auth-moost's `AuthController` login/refresh endpoints and bundled workflows — consumers don't pay the decoration tax.
- **Bundled workflows** (login + MFA, recovery, invite) work end-to-end with single-use magic-link semantics (WF-RECOVERY-03, WF-INVITE-05).
- **Custom workflows** with persistent state via `AsWfStore` resume across server restart (WF-CUSTOM-02 confirmed).
- **Lockout** correctly triggers on failed-login threshold and auto-unlocks after duration (AUTH-05).
- **JWT alg=none / forged tokens** are rejected (AUTH-14, SEC-07).
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
