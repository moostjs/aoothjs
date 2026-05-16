# E2E_STORIES — Test Scenario Catalog

This document enumerates every behavior the `@aoothjs/e2e-demo` app must exercise. Stories are grouped by domain, each with: a short description, the setup it depends on, and the acceptance criteria a passing e2e test must verify.

Stories drive both the **app design** (what models/roles/actions/workflows must exist — captured in [E2E_APP.md](./E2E_APP.md)) and the **test suite** (what assertions the tests must make).

Story IDs follow `<DOMAIN>-<NN>`. Domains:

- **AUTH** — REST auth controller correctness
- **WF** — workflows (login/MFA, recovery, invite, custom)
- **ISO** — ARBAC tenant isolation
- **UNION** — ARBAC multi-role union semantics
- **PROJ** — ARBAC field-level projection
- **ACT** — ARBAC per-action gating + custom actions
- **CTRL** — Uniquery `$controls` correctness under ARBAC
- **WRITE** — write-side enforcement (allowedFields whitelist, forced `set`)
- **META** — `/meta` overlay (action/CRUD visibility)
- **SEC** — adversarial / attack vectors
- **DX** — developer ergonomics

---

## AUTH — REST Auth Controller

### AUTH-01 — login happy path

**Setup:** active user with known password.
**Acceptance:**

- `POST /auth/login` with valid `{ username, password }` → 200, body `{ userId, accessToken, refreshToken, accessExpiresAt, refreshExpiresAt }`.
- `accessExpiresAt > now`, `refreshExpiresAt > accessExpiresAt`.
- Subsequent `GET /auth/status` with `Authorization: Bearer <accessToken>` → 200, returns `AuthContext`.

### AUTH-02 — login with wrong password

**Acceptance:** 401, body contains `Invalid credentials` (NOT `Unknown user`).

### AUTH-03 — login with unknown username

**Acceptance:** 401, body identical to AUTH-02 (enumeration resistance).

### AUTH-04 — login with locked account

**Setup:** `UserService.lockAccount(username, "manual", 60_000)`.
**Acceptance:** 423 with reason; cannot bypass by retrying with valid password.

### AUTH-05 — login auto-lockout after N failures

**Setup:** lockout config `threshold: 3, duration: 5_000`.
**Acceptance:**

- 3 failed logins → 4th attempt with valid password yields 423.
- Wait > 5s → next valid attempt succeeds (auto-unlock); `account.failedLoginAttempts` reset.

### AUTH-06 — refresh happy path

**Setup:** logged in.
**Acceptance:**

- `POST /auth/refresh` with `{ refreshToken }` → 200, new pair.
- For `rotation: "always"`: old refresh now invalid (next refresh with same → 401).

### AUTH-07 — refresh reuse triggers theft response

**Setup:** rotation `always`. Logged in twice (two devices) with separate refresh tokens.
**Acceptance:** after rotating device-A token, replaying old device-A token → 401 AND device-B's tokens are also revoked (`revokeAllForUser`).

### AUTH-08 — refresh with invalid/missing token

**Acceptance:** 401 `Missing refresh token` / `Invalid refresh token`.

### AUTH-09 — logout revokes both tokens

**Acceptance:** after `POST /auth/logout`, both access and refresh tokens are rejected.

### AUTH-10 — logout swallows revoke errors

**Setup:** logout twice in a row.
**Acceptance:** second call still returns `{ ok: true }` (no 500).

### AUTH-11 — `/auth/status` is protected

**Acceptance:** without bearer → 401; with valid bearer → returns `AuthContext`.

### AUTH-12 — change password requires current password

**Acceptance:**

- with wrong current → 401.
- with weak new (policy violation) → 400 with policy error list.
- with new == one of historic → 400 (history defense).
- with valid → 200.

### AUTH-13 — password change cascade revokes ALL sessions

**Setup:** logged in on two simulated devices.
**Acceptance:** after `/auth/password`, both devices' tokens are rejected; user must re-login.

### AUTH-14 — JWT alg=none / forged token rejected

**Acceptance:** request with hand-crafted `eyJhbGciOiJub25lIn0...` → 401 (no panic).

### AUTH-15 — expired token rejected

**Setup:** `accessTtl: 1_000`. Login, wait 2s.
**Acceptance:** `/auth/status` → 401.

### AUTH-16 — bearer wins over cookie when both present

**Setup:** `enableCookie: true`, `enableBearer: true`. Login → cookie set. Then send a request with a forged invalid Bearer header AND the valid cookie.
**Acceptance:** request fails (Bearer is the source of truth); logging in via cookie alone works when no Authorization header present.

### AUTH-17 — `@Public()` route reachable without token

**Acceptance:** `GET /health` → 200 even with no Authorization header.

### AUTH-18 — concurrent token limit

**Setup:** `maxConcurrent: 2`, `onLimit: "evict-oldest"`.
**Acceptance:** issuing a 3rd access token invalidates the 1st; 2nd remains valid.

---

## WF — Workflows

### WF-LOGIN-01 — credentials step (no MFA)

**Setup:** user without MFA enabled. Trigger via `POST /wf/public { wfid: "auth.login" }`.
**Acceptance:**

- Step `credentials` returns form schema for `LoginCredentialsForm`.
- Submit valid credentials → workflow finishes immediately at `issue` step (MFA skipped); response includes tokens.

### WF-LOGIN-02 — MFA required branch

**Setup:** user with confirmed `totp` MFA method.
**Acceptance:**

- After `credentials`, workflow yields `MfaCodeForm`.
- Submit wrong TOTP → step re-prompts with error `code: "Invalid code"`.
- Submit correct TOTP (computed from secret + clock) → workflow finishes; tokens issued.

### WF-LOGIN-03 — MFA bypass attempt rejected

**Acceptance:** trying to advance past `mfa` step with `__skip: true` or empty payload → step still requires valid code.

### WF-RECOVERY-01 — known email triggers email outlet

**Setup:** captured `EmailSender`.
**Acceptance:**

- POST `/wf/public { wfid: "auth.recovery", input: { email } }` → response with handle.
- Email captured: `kind: "recovery.magicLink"`, `recipient: email`, `url: <link>`, `expiresAt > now`.
- Resume via `?wfs=<token>` from email URL → form `SetPasswordForm`.
- Submit valid new password → tokens issued; user can log in with new password; old password rejected.

### WF-RECOVERY-02 — unknown email enumeration resistance

**Setup:** no user with that email.
**Acceptance:** response is identical shape to known-email case (`{ sent: true }` finished); no email captured.

### WF-RECOVERY-03 — magic link is single-use

**Setup:** complete WF-RECOVERY-01.
**Acceptance:** replaying the same `?wfs=<token>` URL → 404 / "handle not found".

### WF-RECOVERY-04 — magic link expires

**Setup:** configure `recoveryTokenTtlMs: 1_000`.
**Acceptance:** wait 2s, then resume with token → expired error.

### WF-RECOVERY-05 — recovery does NOT revoke existing sessions

(documented behavior; unlike password change cascade)
**Acceptance:** session issued before recovery is still valid after recovery completes.
_(or — if we add cascade — flip the assertion. For v1, assert current behavior.)_

### WF-INVITE-01 — admin-gated invite create

**Setup:** admin logs in. `POST /wf/admin { wfid: "auth.invite", input: { email, roles: "member,viewer" } }`.
**Acceptance:**

- Non-admin caller → 403.
- Admin: user created (active=false), invite email captured with `kind: "invite.magicLink"`, `metadata.roles: ["member","viewer"]`.

### WF-INVITE-02 — invite accept activates user + applies roles

**Setup:** complete WF-INVITE-01.
**Acceptance:**

- Resume via `?wfs=<inviteToken>` on `/wf/public` → form `SetPasswordForm`.
- Submit new password → user activated, tokens issued, roles assigned.
- Logged-in user has `[member, viewer]` roles per `arbac.evaluate` in subsequent calls.

### WF-INVITE-03 — invite rejects existing user (no enumeration concern; admin-only)

**Acceptance:** invite for email already in DB → 409.

### WF-INVITE-04 — invite link expires

**Setup:** `inviteTokenTtlMs: 2_000`.
**Acceptance:** resume after expiry → expired error.

### WF-INVITE-05 — invite link single-use

**Acceptance:** replay token → 404.

### WF-CUSTOM-01 — `project.handover` happy path

**Setup:** custom workflow `project.handover` with steps: `selectTarget` → `confirm` → `notify` → `commit`. Persistent state via `AsWfStore`. Outlet emits confirmation email to current owner.
**Acceptance:**

- Owner triggers; selects new owner; confirms → `notify` step emits email; resume from email URL → `commit` step transfers ownership in DB.
- Throughout, ARBAC enforces only owner or admin can run this workflow.

### WF-CUSTOM-02 — handover transient state survives mid-flow

**Acceptance:** a `handle` returned after step 1 is resumable even after server restart (state persisted via `AsWfStore`).

### WF-CUSTOM-03 — handover transient context purged after commit

**Acceptance:** after `commit`, `wf_states` row is deleted; handle no longer resumable.

### WF-CUSTOM-04 — non-owner cannot trigger handover

**Acceptance:** member triggers project.handover for a project they don't own → 403.

### WF-FORM-01 — partial form on resume

**Acceptance:** when resuming a workflow, fields previously collected are present in the form's `passContext`; user only fills new fields.

### WF-FORM-02 — invalid form rejected with field-level errors

**Acceptance:** submit `SetPasswordForm` with `confirmPassword` mismatch → form returned with `confirmPassword: "..."` error.

---

## ISO — Tenant Isolation

### ISO-01 — list scoped to caller's tenant

**Setup:** tenant A user calls `GET /tasks/query`.
**Acceptance:** response contains only rows where `tenantId == A`; never any from tenant B.

### ISO-02 — single-record fetch across tenant returns 404

**Setup:** task `T_B` belongs to tenant B; tenant A user knows the id.
**Acceptance:** `GET /tasks/one/T_B` → 404 (not 403; not found within scope).

### ISO-03 — composite key fetch across tenant

**Acceptance:** `GET /documents/one?ownerUsername=otherbob` (cross-tenant) → 404.

### ISO-04 — pagination count respects scope

**Acceptance:** `GET /tasks/pages?$count=true` returns count only of in-scope rows; not the global count.

### ISO-05 — write filter enforced on `update`

**Setup:** task `T_B` in tenant B; tenant A admin sends PATCH with `{ id: T_B, ... }`.
**Acceptance:** `result.matchedCount === 0` (no rows updated). The implementation must AND the user filter with the scope filter; do NOT trust the body's `id` alone.

### ISO-06 — write filter enforced on `delete`

**Acceptance:** `DELETE /tasks/T_B` from tenant A → `deletedCount: 0` or 404; T_B unchanged.

### ISO-07 — insert sets tenantId from scope, ignores body

**Setup:** tenant A user inserts a task with `body.tenantId = "B"`.
**Acceptance:** stored `tenantId === "A"` (forced by scope `set`).

### ISO-08 — superadmin sees all tenants

**Acceptance:** superadmin's `/tasks/query` returns rows from every tenant.

### ISO-09 — tenant deletion cascade is OUT OF SCOPE for arbac

(arbac doesn't manage cascade; this is a doc story to make the boundary explicit)

---

## UNION — Multi-Role Union

### UNION-01 — two complementary roles broaden filter

**Setup:** user has `[viewer, projectMember]`; viewer scope = `tenantId=A`, projectMember scope = `ownerUsername=self`.
**Acceptance:** `GET /projects/query` returns ALL tenant-A projects PLUS projects owned by self in any tenant — i.e., the OR of the two scope filters.

### UNION-02 — two scoped roles broaden field projection

**Setup:** role X projection `{ title:1, status:1 }`, role Y projection `{ title:1, dueDate:1 }`.
**Acceptance:** user with both can read `title`, `status`, `dueDate` on every row.

### UNION-03 — deny short-circuits union

**Setup:** role X allows `tasks.update`, role Y has explicit `effect: "deny"` on `tasks.update`.
**Acceptance:** PATCH /tasks → 403 even though X allows.

### UNION-04 — superadmin role overlapped with viewer

**Acceptance:** scope union behaves correctly (broader access wins per filter union).

---

## PROJ — Field-Level Projection

### PROJ-01 — viewer cannot read sensitive fields

**Setup:** `viewer` projection `{ password: 0, mfa: 0, account: 0, secretNotes: 0, email: 0 }` on `users`.
**Acceptance:** `GET /users/query` → response rows have those keys absent (not null, ABSENT).

### PROJ-02 — `$select` cannot escape projection

**Setup:** viewer.
**Acceptance:** `GET /users/query?$select=password,mfa` → response either omits those fields or returns 400; never leaks them.

### PROJ-03 — projection union (multi-role) widens but never broader than total schema

**Acceptance:** as in UNION-02, plus: a field NOT in any role's projection remains hidden.

### PROJ-04 — projection on `$with` relations

**Setup:** viewer reads tasks with `$with=[{path: "comments"}]`.
**Acceptance:** comments expanded but with viewer's comment-projection applied (not the full comment schema).

### PROJ-05 — `/one` honors projection

**Acceptance:** `GET /users/one/<id>` returns only allowed fields.

### PROJ-06 — projection uses additive union semantics

**Acceptance:** include-mode `{title:1}` ∪ exclude-mode `{password:0}` resolves correctly per `unionProjections` rules; document the resolved mode in the test.

---

## ACT — Per-Action Gating

### ACT-01 — read action allowed, write denied

**Setup:** `viewer` with `allowTableRead`.
**Acceptance:** GET/query/pages/one/meta succeed; POST/PATCH/PUT/DELETE → 403.

### ACT-02 — custom action gated by name

**Setup:** member can `tasks.markDone` but not `tasks.delete`.
**Acceptance:** `POST /tasks/actions/markDone` → 200; `POST /tasks/actions/delete` → 403.

### ACT-03 — `@DbAction` name resolution

**Setup:** action method named `mark` decorated `@DbAction("markDone")`.
**Acceptance:** ARBAC rule `tasks.markDone` (not `tasks.mark`) controls access — verifying `atscript_db_action.name` is honored over `id`/method-name.

### ACT-04 — undecorated route still requires authentication

_(post-ISSUE-4: arbac-only bypass no longer exists. A route with no `@ArbacResource`/`@ArbacAction` short-circuits the ARBAC interceptor by virtue of having no resource/action — but auth-moost's global bearer guard still demands a token unless `@Public()` is applied.)_
**Acceptance:** route lacking both `@Public()` and `@ArbacResource`/`@ArbacAction` still requires a valid token; ARBAC just no-ops because there's nothing to evaluate.

### ACT-05 — `disabled: perRow` predicate enforced

**Setup:** task already `done`; member calls `markDone` again.
**Acceptance:** action returns error from moost-db (`onDisabledRows: "reject"`).

### ACT-06 — moost-db method-name aliases

**Acceptance:** ARBAC rule `tasks.one` allows BOTH `getOne` and `getOneComposite` HTTP routes (verify `literal method name passthrough`).

### ACT-07 — `tasks.remove` rule allows BOTH `removeComposite` and `remove`

**Acceptance:** parallel to ACT-06 for delete.

---

## CTRL — Uniquery `$controls`

**Note:** moost-db / @uniqu/core mechanics (operator semantics, pagination format, sort/select/count/groupBy correctness) are NOT tested here — they belong in those repos' test suites. This section asserts that aoothjs's ARBAC scope is preserved across user-supplied controls.

### CTRL-05 — `$with` relation expansion (SKIPPED)

**Setup:** task has `comments`. Member queries with `$with=[{path: "comments"}]`.
**Acceptance:** rows include `comments: [...]` array; comments are subject to ARBAC on the `comments` resource (cross-cutting).
**Skip rationale:** `$with` relation expansion against an actually-declared nav prop. Skipped because moost-db@0.1.75's `@TableController` typing rejects tables with non-empty NavType (variance issue). FK constraints landed in Phase 2 but the nav props (`@db.rel.to`/`@db.rel.from`) were dropped to keep the controllers compiling. Re-enable when moost-db typing accepts wider tables.

### CTRL-07 — scope holds across operator forms

**Acceptance:** for each user-supplied filter operator form (`$eq`, `$ne`, `$in`, `$nin`, `$gt`, `$gte`, `$lt`, `$lte`, `$regex`), all returned rows are tenant-scoped — no operator escapes scope. Per-operator semantic correctness is out-of-scope (belongs to @uniqu/core).

### CTRL-08 — logical `$or` / `$and` / `$not`

**Acceptance:** `$or` in user filter is itself ANDed with scope filter (cannot escape).

### CTRL-EX-01 — viewer `$with` denied → 403

**Setup:** viewer `controls.$with: false`.
**Acceptance:** `GET /tasks/query?$with=comments` as t1_eve → 403 with body containing `"$with"`.

### CTRL-EX-02 — viewer `$groupBy` denied → 403 (SKIPPED — moost-db quirk)

**Acceptance:** `GET /tasks/query?$groupBy=status&$select=status,count(*):cnt` as t1_eve → 403.
**Skip rationale:** moost-db@0.1.75's `query()` short-circuits to `aggregate()` whenever `$groupBy.length > 0` and SKIPS `validateParsed`. Our `validateControls` override is therefore never invoked for $groupBy queries. Union/whitelist semantics are still covered by the unit tests in `packages/arbac/src/scope/controls.spec.ts`. Re-enable when moost-db routes the aggregate path through `validateParsed`.

### CTRL-EX-03 — admin can use `$with` (silence wins union)

**Acceptance:** `GET /tasks/query?$with=anything` as t1_dave → 200 OR 400-from-moost-db (relation not declared) — the key is it's NOT 403 from arbac.

### CTRL-EX-04 — multi-role union: silence wins (alice = member+viewer; member silent on `$with` → allowed)

**Acceptance:** `GET /tasks/query?$with=comments` as t1_alice → NOT 403 (member's silence overrides viewer's denial). May be 400 from moost-db (relation not declared) — that's a moost-db typing limitation, not an ARBAC failure.

### CTRL-EX-05 — multi-role union: both deny → 403 (SKIPPED — moost-db quirk)

**Setup:** ALL alice's roles deny `$groupBy` (member denies, viewer denies).
**Acceptance:** `GET /tasks/query?$groupBy=status` as t1_alice → 403.
**Skip rationale:** Same moost-db@0.1.75 quirk as CTRL-EX-02 — $groupBy bypasses `validateParsed`. Union semantics covered by unit tests.

### CTRL-EX-06 — gating works on `/pages` route too

**Acceptance:** `GET /tasks/pages?$page=1&$size=10&$with=comments` as t1_eve → 403.

### CTRL-EX-07 — silence on a control means allowed (member uses `$with`)

**Acceptance:** `GET /comments/query?$with=task` as t1_bob (member only) → NOT 403. May be 400 from moost-db (relation not declared).

### CTRL-EX-08 — denied on `/one` route too

**Acceptance:** `GET /tasks/one/<id>?$with=comments` as t1_eve → 403 if `/one` accepts `$with` at all (some moost-db routes may not pass it through `validateControls`). If the `/one` route doesn't validate `$with`, it's a moost-db gap, not ours; the test documents the actual behavior.

---

## WRITE — Write-Side Enforcement

### WRITE-01 — `allowedFields` whitelists `update` payload

**Setup:** member can `update` tasks but only fields `[title, description, status]`.
**Acceptance:** PATCH `{ id, title, internalNotes: "..."}` → `internalNotes` ignored; row unchanged on that field.

### WRITE-02 — `set` forces fields on `insert`

**Setup:** member's `tasks.insert` scope sets `tenantId, creatorUsername, assigneeUsername` to self.
**Acceptance:** body's attempted overrides ignored; persisted row has scope-derived values.

### WRITE-03 — `set` forces fields on custom actions

**Acceptance:** `actions/new` merges scope `set` after form input.

### WRITE-04 — write to `/replace` (PUT) also enforces allowedFields + set

**Acceptance:** PUT respects same constraints as PATCH.

### WRITE-05 — bulk insert/update array path

**Acceptance:** array body each item enforced; one item with bad data is per-item filtered (not silently included).

### WRITE-06 — denied write returns 403, not 500

**Acceptance:** PATCH on resource where caller lacks `update` → 403 with informative message.

### WRITE-07 — auto-set fields cannot be unset by client

**Acceptance:** `body.tenantId = null` ignored.

---

## META — Metadata Overlay

### META-01 — `meta.actions` filters by privilege

**Setup:** viewer cannot run `delete`/`markDone`.
**Acceptance:** `GET /tasks/meta` returns `actions: []` (or only actions viewer can run); admin sees full set.

### META-02 — `meta.crud` filters by privilege

**Acceptance:** viewer's `meta.crud` excludes `insert`, `update`, `replace`, `remove`.

### META-03 — `meta` itself requires `meta` privilege

**Setup:** `allowTableRead` includes `meta`. Role without read.
**Acceptance:** `GET /tasks/meta` → 403.

### META-04 — `meta/form/:name` schema is unchanged regardless of role

**Acceptance:** form schema is global (not user-scoped); but the action mounting it may not be visible in `meta.actions` for some roles.

---

## SEC — Adversarial / Attack Vectors

**Note:** Stories that test other repos' resilience (HTTP body parser DoS, SQL parameterization, render-side XSS, CSRF middleware) are NOT included — those belong in @wooksjs / @atscript/db / consumer-app test suites.

### SEC-01 — filter injection via `$or` to escape tenant

**Attack:** `GET /tasks/query?$or[0][tenantId]=B&$or[1][tenantId]=A`.
**Acceptance:** scope's `tenantId=A` filter ANDs with user filter; final query yields only `A` rows.

### SEC-02 — projection escape via `$select`

**Attack:** viewer `?$select=password,mfa,account.lockEnds`.
**Acceptance:** denied fields omitted from response.

### SEC-03 — PK guess across tenant

(See ISO-02; here verify timing safety: 404 is constant-time vs in-tenant 200.)
**Acceptance:** response time roughly matches in-tenant 404; no timing oracle.

### SEC-04 — composite key bypass via param overload

**Attack:** `GET /tasks/one?id=<foreign>&tenantId=<other>`.
**Acceptance:** still returns 404; scope wins.

### SEC-05 — mass-assignment via insert (extra field)

**Attack:** member POSTs `{ title, status, roles: ["admin"] }` to `/users` (where allowedFields excludes `roles`).
**Acceptance:** `roles` not persisted.

### SEC-06 — mass-assignment via update (role escalation)

**Attack:** member PATCHes own user `{ id: self, roles: ["admin"] }`.
**Acceptance:** `roles` not persisted (allowedFields excludes it). Even via `users.assignRoles` action, only admin can call it.

### SEC-07 — JWT with `alg: "none"`

**Attack:** craft and send.
**Acceptance:** rejected (already covered in unit; verify integration).

### SEC-08 — JWT with swapped signature algorithm

**Attack:** craft `alg: HS256` with public key as secret.
**Acceptance:** rejected.

### SEC-09 — refresh-token reuse triggers theft response

(See AUTH-07; double-check end-to-end at HTTP layer.)

### SEC-10 — magic-link replay

(See WF-RECOVERY-03; verify single-use semantics work on `getAndDelete`.)

### SEC-11 — magic-link cross-user replay

**Attack:** alice's recovery token sent by mallory.
**Acceptance:** mallory cannot use alice's token (handle bound to original user via wf context).

### SEC-12 — workflow handle replay across roles

**Attack:** capture handle from admin's invite step; use it as a non-admin trigger.
**Acceptance:** still requires admin RBAC on `/wf/admin`.

### SEC-13 — lockout brute force

(See AUTH-05.)

### SEC-14 — login enumeration

(See AUTH-02 / AUTH-03 — test both at REST and at workflow layer.)

### SEC-15 — recovery enumeration

(See WF-RECOVERY-02.)

### SEC-16 — password policy bypass

**Attack:** submit weak password during recovery / invite / change.
**Acceptance:** uniformly rejected (400 with policy errors).

### SEC-17 — password history bypass

**Attack:** rotate through N+1 passwords to reuse the original.
**Acceptance:** with `historyLength: 5`, reuse within last 5 → rejected.

### SEC-18 — TOTP replay

**Attack:** capture a valid TOTP and submit again within the same period.
_Note:_ HOTP-style replay defense isn't standard for TOTP; accept replay-within-window as known. Story documents this.
**Acceptance:** within same 30s period, same code may succeed twice (documented).

### SEC-19 — TOTP brute force

**Attack:** submit 10000 random codes.
**Acceptance:** lockout policy on MFA failures kicks in (or document gap).

### SEC-24 — concurrent password change race

**Attack:** two simultaneous `/auth/password` requests from same user.
**Acceptance:** one succeeds, the other fails (or both succeed atomically); no torn state.

### SEC-25 — `@Public()` resolution on a class-level decoration

**Attack:** confirm that ONLY methods explicitly marked or controllers entirely marked are public; nested decorators don't accidentally inherit.

### SEC-26 — empty-rules role yields deny-all

**Setup:** role with no rules registered.
**Acceptance:** user with only that role → all resources denied.

### SEC-27 — wildcard `**` in resource doesn't match unintended

**Acceptance:** rule `resource: "tasks.**"` should NOT match `tasks_secret` or `tasksprivate`. Glob anchoring tested.

### SEC-28 — invite acceptance can be hijacked if email leaked

_(documented limitation: anyone with the magic link can accept. Test that step 3 input must include the password — mere visit doesn't activate.)_

### SEC-29 — admin self-demote

**Attack:** admin removes their own `admin` role via `users.assignRoles`.
**Acceptance:** allowed (not blocked by ARBAC); document need for org-level invariant if undesired. Optional: assert at least one admin remains via custom check (out of scope for this lib).

### SEC-30 — refresh from logged-out session

**Attack:** logout then refresh with old refresh token.
**Acceptance:** 401 (refresh revoked at logout).

### SEC-32 — denylist memory store size growth

_(documented: in-memory denylist grows; `cleanup()` purges expired. Test that calling cleanup reduces size.)_

---

## DX — Developer Ergonomics

### DX-01 — empty subclass works

**Acceptance:** `class TasksController extends AsArbacDbController<typeof Task> {}` (no body) compiles and serves all CRUD with ARBAC enforced.

### DX-02 — error messages on missing privilege are actionable

**Acceptance:** 403 body includes resource + action: `Insufficient privileges for action "tasks.update" on resource "tasks"`.

### DX-03 — TS types catch typos

**Acceptance:** `defineRole<UserAttrs, ArbacDbScope>().allow("tasks", "fooo", ...)` is allowed at runtime (string types) — not a TS error per se, but document that the e2e suite catches this via behavior tests.

### DX-04 — `@Public()` on bundled auth-moost controllers ships out of the box

**Acceptance:** consumer doesn't need to manually decorate `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` or the public `AuthController` endpoints (`login`, `refresh`). Confirm by registering them WITHOUT extra decoration and calling `app.applyGlobalInterceptors(arbacAuthorizeInterceptor)`.

### DX-05 — `useArbac().evaluate()` defaults work in handlers

**Acceptance:** inside a handler, `evaluate()` (no args) auto-resolves resource/action from controller+method metadata.

### DX-06 — privilege factories compose

**Acceptance:** `defineRole().use(allowTableRead("x"), allowTableAction("x", "publish"))` works and yields the union.

### DX-07 — `setupAuthWorkflows` `workflows: { invite: false }` skips registration

**Acceptance:** `/wf/admin` triggering `auth.invite` after `invite: false` → 404 / "workflow not registered".

### DX-08 — `authEndpointsEnabled: false` skips AuthController

**Acceptance:** `/auth/login` → 404 when endpoints disabled.

---

## Coverage Matrix

| Area                                              | Story IDs                                                                                                               |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Auth REST correctness (goal #4)                   | AUTH-01..18                                                                                                             |
| Workflows + outlets + email + OTP (#5)            | WF-LOGIN-01..03, WF-RECOVERY-01..05, WF-INVITE-01..05, WF-CUSTOM-01..04, WF-FORM-01..02                                 |
| Multi-user/role + per-field/action/$controls (#1) | ISO-01..09, UNION-01..04, PROJ-01..06, ACT-01..07, CTRL-05, CTRL-07, CTRL-08, CTRL-EX-01..08, WRITE-01..07, META-01..04 |
| Attack vectors (#2)                               | SEC-01..19, SEC-24..30, SEC-32                                                                                          |
| DX (#3)                                           | DX-01..08                                                                                                               |

CTRL deletions (CTRL-01, 02, 03, 04, 06, 09, 10) and SEC deletions (SEC-20, 21, 22, 23, 31) cover concerns that belong to other repos (moost-db / @uniqu/core / @wooksjs/event-http / @atscript/db / consumer render layer) — see the per-section Notes above.

Each story is named so failing tests pinpoint the story they violate.
