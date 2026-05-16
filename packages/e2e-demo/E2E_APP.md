# E2E_APP — Design

This document specifies the **app** that backs the test suite described in [E2E_STORIES.md](./E2E_STORIES.md). Every model, role, action, and workflow listed below must exist so the stories have something to assert against.

The package is **private** (`"private": true` in `package.json`) — it is not published. It exists solely as a fixture for the e2e test suite.

---

## 1. Goals and Non-Goals

**In scope:**

- Multi-tenant data model with cross-cutting relationships (project → tasks → comments; documents with classification; audit log).
- Six roles with distinct read/write/projection/scope semantics covering: tenant isolation, ownership, department membership, field-level gating, custom actions, role union.
- Bundled auth workflows (`auth.login`, `auth.recovery`, `auth.invite`) + one custom workflow (`project.handover`) exercising outlets, persistent state, and resume tokens.
- A captured `EmailSender` (used by the test harness; default in dev mode is `ConsoleEmailSender`).
- A seed script that deterministically populates tenants, users, departments, projects, tasks, comments, documents so tests can assert exact row counts/contents.
- An HTTP test harness: boots the app in-process on an ephemeral port, returns a fetch client + helpers (`loginAs(role)`, captured email queue, etc.).

**Out of scope:**

- Frontend UI / browser automation. Stories test the HTTP API directly. (If we later want a browser integration sanity check, that can be a separate test file using the `playwright-cli` skill — but the goals listed by the user are all API-shape.)
- CSRF / CORS hardening (documented as consumer responsibility).
- Production-grade observability (telemetry, structured logging).
- Cluster / distributed-store semantics.

---

## 2. File Tree

```
packages/e2e-demo/
├── E2E_STORIES.md
├── E2E_APP.md
├── README.md                       (short consumer-facing intro)
├── package.json                    (private:true)
├── tsconfig.json
├── vite.config.ts                  (atscript() plugin; vp test wiring)
├── atscript.config.mts             (ts() + dbPlugin() + arbac plugin())
├── src/
│   ├── main.ts                     (Moost bootstrap; entry for `pnpm dev`)
│   ├── app.ts                      (factory: builds Moost app; reused by tests)
│   ├── env.ts                      (read PORT, DB_PATH, FRONTEND_URL, etc. with test-friendly defaults)
│   ├── db.ts                       (DbSpace + tables; supports in-memory mode)
│   ├── aooth.ts                    (authCredential, userService, arbacUserReader, buildMagicLinkUrl)
│   ├── email/
│   │   ├── console-email-sender.ts (production-default; logs)
│   │   └── capture-email-sender.ts (test-only; pushes to in-memory queue)
│   ├── wf-store.ts                 (AsWfStore)
│   ├── roles/
│   │   ├── index.ts                (exports allRoles)
│   │   ├── attrs.ts                (UserAttrs type)
│   │   ├── superadmin.ts
│   │   ├── admin.ts
│   │   ├── manager.ts
│   │   ├── member.ts
│   │   ├── viewer.ts
│   │   └── guest.ts
│   ├── models/
│   │   ├── tenant.as
│   │   ├── user.as
│   │   ├── department.as
│   │   ├── project.as
│   │   ├── task.as
│   │   ├── comment.as
│   │   ├── document.as
│   │   ├── audit.as
│   │   └── wf-state.as
│   ├── controllers/
│   │   ├── health.controller.ts
│   │   ├── tenants.controller.ts
│   │   ├── users.controller.ts
│   │   ├── departments.controller.ts
│   │   ├── projects.controller.ts
│   │   ├── tasks.controller.ts
│   │   ├── comments.controller.ts
│   │   ├── documents.controller.ts
│   │   ├── audit.controller.ts
│   │   └── wf-trigger.controller.ts
│   ├── workflows/
│   │   ├── handover.workflow.ts    (custom: project.handover)
│   │   └── handover.forms.as       (HandoverTargetForm, HandoverConfirmForm)
│   ├── seed.ts                     (deterministic data seeding)
│   └── scripts/
│       └── init-db.ts              (one-shot DB sync + seed for `pnpm db:init`)
└── test/
    ├── harness.ts                  (boot app, fetch helpers, login helpers, email queue)
    ├── auth.spec.ts                (AUTH-01..18)
    ├── wf-login.spec.ts            (WF-LOGIN-01..03)
    ├── wf-recovery.spec.ts         (WF-RECOVERY-01..05)
    ├── wf-invite.spec.ts           (WF-INVITE-01..05)
    ├── wf-handover.spec.ts         (WF-CUSTOM-01..04)
    ├── arbac-isolation.spec.ts     (ISO-01..09)
    ├── arbac-union.spec.ts         (UNION-01..04)
    ├── arbac-projection.spec.ts    (PROJ-01..06)
    ├── arbac-actions.spec.ts       (ACT-01..07)
    ├── arbac-meta.spec.ts          (META-01..04)
    ├── arbac-write.spec.ts         (WRITE-01..07)
    ├── controls.spec.ts            (CTRL-01..10)
    ├── security.spec.ts            (SEC-01..32, possibly split)
    └── dx.spec.ts                  (DX-01..08)
```

---

## 3. Models

All models use `@atscript/db` annotations. Atscript primitive tags (`number.timestamp`, `string`) inferred from the type. Where useful, fields carry `@arbac.attribute` (so they flow into `UserAttrs` via `AtscriptArbacUserProvider`) or `@arbac.role` (for role lookup).

### 3.1 `tenant.as`

```
import { } from "@atscript/db"

@db.table 'tenants'
@db.http.path '/tenants'
interface Tenant {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @expect.maxLength 64
    @db.index.unique 'tenants_name_unique'
    name: string

    @expect.maxLength 128
    domain?: string

    @meta.required
    @ui.form.options 'free', 'free'
    @ui.form.options 'pro', 'pro'
    @ui.form.options 'enterprise', 'enterprise'
    plan: 'free' | 'pro' | 'enterprise'

    @db.default.now
    createdAt: number.timestamp
}
```

### 3.2 `user.as`

Extends `AoothArbacUserCredentials` (which already declares `roles: string[]` with `@arbac.role`). Adds tenant/department attrs and a couple of e2e-only fields.

```
import { AoothArbacUserCredentials } from '@aoothjs/arbac-moost/atscript/models'

@db.table 'users'
@db.http.path '/users'
interface DemoUser extends AoothArbacUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @arbac.attribute
    @meta.required
    @expect.maxLength 64
    tenantId: string

    @arbac.attribute
    @expect.maxLength 64
    departmentId?: string

    @expect.maxLength 128
    email?: string

    @expect.maxLength 1000
    secretNotes?: string

    @db.default.now
    createdAt: number.timestamp
}
```

Sensitive fields inherited from `AoothArbacUserCredentials`: `password.*`, `mfa.*`, `account.*`. All are projection-restricted for non-admin roles.

### 3.3 `department.as`

```
@db.table 'departments'
@db.http.path '/departments'
interface Department {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @expect.maxLength 64
    tenantId: string

    @meta.required
    @expect.maxLength 64
    name: string

    @db.default.now
    createdAt: number.timestamp
}
```

### 3.4 `project.as`

```
@db.table 'projects'
@db.http.path '/projects'
interface Project {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required tenantId: string

    @meta.required
    @expect.maxLength 200
    name: string

    @meta.required
    @expect.maxLength 128
    ownerUsername: string

    departmentId?: string

    @meta.required
    @ui.form.options 'public', 'public'
    @ui.form.options 'team', 'team'
    @ui.form.options 'private', 'private'
    visibility: 'public' | 'team' | 'private'

    secretBudget?: number

    @db.default.now createdAt: number.timestamp
}
```

### 3.5 `task.as`

```
@db.table 'tasks'
@db.http.path '/tasks'
interface Task {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required tenantId: string

    @meta.required projectId: string

    @meta.required
    @expect.maxLength 200
    title: string

    @expect.maxLength 4000
    description?: string

    @meta.required
    @expect.maxLength 128
    creatorUsername: string

    @expect.maxLength 128
    assigneeUsername?: string

    @meta.required
    @ui.form.options 'open', 'open'
    @ui.form.options 'in_progress', 'in_progress'
    @ui.form.options 'done', 'done'
    status: 'open' | 'in_progress' | 'done'

    @ui.form.options 'low', 'low'
    @ui.form.options 'medium', 'medium'
    @ui.form.options 'high', 'high'
    priority?: 'low' | 'medium' | 'high'

    dueDate?: number.timestamp

    @expect.maxLength 4000
    internalNotes?: string

    @db.default.now createdAt: number.timestamp
    @db.default.now updatedAt: number.timestamp
}

interface NewTaskForm {
    @meta.required projectId: string
    @meta.required @expect.maxLength 200 title: string
    @expect.maxLength 4000 description?: string
    @expect.maxLength 128 assigneeUsername?: string
    @ui.form.options 'low', 'low'
    @ui.form.options 'medium', 'medium'
    @ui.form.options 'high', 'high'
    priority?: 'low' | 'medium' | 'high'
    dueDate?: number.timestamp
}

interface AssignTaskForm {
    @meta.required @expect.maxLength 128 assigneeUsername: string
}
```

### 3.6 `comment.as`

```
@db.table 'comments'
@db.http.path '/comments'
interface Comment {
    @meta.id @db.default.uuid id: string
    @meta.required tenantId: string
    @meta.required taskId: string
    @meta.required @expect.maxLength 128 authorUsername: string
    @meta.required @expect.maxLength 4000 body: string
    @db.default.now createdAt: number.timestamp
}
```

### 3.7 `document.as`

```
@db.table 'documents'
@db.http.path '/documents'
interface Document {
    @meta.id @db.default.uuid id: string
    @meta.required tenantId: string
    projectId?: string
    @meta.required @expect.maxLength 200 title: string
    @expect.maxLength 65000 body: string
    @meta.required
    @ui.form.options 'public', 'public'
    @ui.form.options 'internal', 'internal'
    @ui.form.options 'confidential', 'confidential'
    classification: 'public' | 'internal' | 'confidential'
    @meta.required @expect.maxLength 128 ownerUsername: string
    @db.default.now createdAt: number.timestamp
}
```

### 3.8 `audit.as`

```
@db.table 'audit_log'
@db.http.path '/audit'
interface AuditEntry {
    @meta.id @db.default.uuid id: string
    @meta.required tenantId: string
    @meta.required @expect.maxLength 128 actor: string
    @meta.required @expect.maxLength 64 action: string
    @meta.required @expect.maxLength 64 resource: string
    recordId?: string
    @expect.maxLength 8000 payload?: string
    @db.default.now createdAt: number.timestamp
}
```

### 3.9 `wf-state.as`

```
import { AsWfStateRecord } from '@atscript/moost-wf/store'

@db.table 'wf_states'
interface DemoWfState extends AsWfStateRecord {
    @meta.id @db.default.uuid id: string
}
```

---

## 4. UserAttrs

The shape that flows into every scope function. Derived from `@arbac.attribute` annotations on `DemoUser`.

```ts
export interface UserAttrs {
  tenantId: string;
  departmentId?: string;
}
```

`AtscriptArbacUserProvider` (extended by the demo's `DemoArbacUserProvider`) builds this automatically by walking `DemoUser`'s annotated props. Scope functions receive `(attrs: UserAttrs, userId: string)` — `userId` is the **username** (JWT subject), not the UUID `id`.

---

## 5. Role Matrix

Six roles. Each entry shows the privilege factory used and the scope it computes. Rows show resource permissions. Columns: `R` = read (query/pages/one/meta), `W` = write (insert/update/replace/remove), `A` = custom actions. Field projection given where applicable.

### Legend

- `tenantFilter(attrs) = { tenantId: attrs.tenantId }`
- `selfOwner(attrs, uid) = { ownerUsername: uid }`
- `selfAssignee(attrs, uid) = { assigneeUsername: uid }`
- `selfCreator(attrs, uid) = { creatorUsername: uid }`
- `selfAuthor(attrs, uid) = { authorUsername: uid }`
- `selfId(attrs, uid) = { username: uid }`
- `deptFilter(attrs) = { departmentId: attrs.departmentId }`
- `visibilityFilter(roles_for_project)` defined inline for projects.

### 5.1 superadmin

| Resource    | Privilege                            | Scope           |
| ----------- | ------------------------------------ | --------------- |
| tenants     | `allowTableWrite("tenants")`         | none (universe) |
| users       | `allowTableWrite("users")`           | none            |
| departments | `allowTableWrite("departments")`     | none            |
| projects    | `allowTableWrite("projects")`        | none            |
| tasks       | `allowTableWrite("tasks")` + actions | none            |
| comments    | `allowTableWrite("comments")`        | none            |
| documents   | `allowTableWrite("documents")`       | none            |
| audit       | `allowTableRead("audit")`            | none            |

Custom actions on `tasks`: `new`, `markDone`, `markInProgress`, `archive`, `assign`, `delete`. Custom actions on `users`: `assignRoles`, `lock`, `unlock`.

### 5.2 admin

Tenant-scoped god mode within own tenant; cannot touch other tenants; cannot modify roles via PATCH `/users` (role changes only via the dedicated `assignRoles` action).

| Resource     | Privilege                                                                                                                                          | Scope filter                                                                           |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| tenants      | `allowTableRead("tenants", { scope: a => ({ filter: { id: a.tenantId } }) })`                                                                      | own tenant only                                                                        |
| users        | `allowTableWrite("users", { scope: a => ({ filter: tenantFilter(a), allowedFields: WRITEABLE_USER_FIELDS_ADMIN, projection: PROJ_USER_ADMIN }) })` | tenant + whitelist (excl. `roles`) + projection masking `password.history`/`mfa.value` |
| departments  | `allowTableWrite("departments", { scope: a => ({ filter: tenantFilter(a), set: { tenantId: a.tenantId } }) })`                                     |                                                                                        |
| projects     | `allowTableWrite("projects", { scope: a => ({ filter: tenantFilter(a), set: { tenantId: a.tenantId } }) })`                                        |                                                                                        |
| tasks        | `allowTableWrite("tasks", { scope: a => ({ filter: tenantFilter(a) }) })` + `allowTableAction("tasks", ALL_TASK_ACTIONS, ...)`                     | per-action scopes force `tenantId`/`creatorUsername` on `new`                          |
| comments     | `allowTableWrite("comments", { scope: a => ({ filter: tenantFilter(a) }) })`                                                                       |                                                                                        |
| documents    | `allowTableWrite("documents", { scope: a => ({ filter: tenantFilter(a) }) })`                                                                      |                                                                                        |
| audit        | `allowTableRead("audit", { scope: a => ({ filter: tenantFilter(a) }) })`                                                                           |                                                                                        |
| auth         | `defineRole().allow("auth", "admin.invite")`                                                                                                       | enables `/wf/admin` for `auth.invite`                                                  |
| users action | `allowTableAction("users", ["assignRoles", "lock", "unlock"], { scope: ... })`                                                                     | tenant-scoped                                                                          |

### 5.3 manager

Read across own tenant; write within own department. Custom task actions on tasks in department.

| Resource    | Privilege                                                                                                                                                                                                                                                                  | Scope                                                                |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| users       | `allowTableRead("users", { scope: a => ({ filter: tenantFilter(a), projection: PROJ_USER_MANAGER }) })`                                                                                                                                                                    | tenant + projection excluding `password.*`, `mfa.value`, `account.*` |
| departments | `allowTableRead("departments", { scope: a => ({ filter: tenantFilter(a) }) })`                                                                                                                                                                                             |                                                                      |
| projects    | `allowTableRead("projects", { scope: a => ({ filter: tenantFilter(a) }) })` + `allowTableAction("projects", ["update"], { scope: a => ({ filter: { ...tenantFilter(a), departmentId: a.departmentId } }) })`                                                               | read all in tenant; write own dept                                   |
| tasks       | `allowTableRead("tasks", { scope: a => ({ filter: tenantFilter(a) }) })` + `allowTableAction("tasks", ["insert","update","markDone","markInProgress","archive","assign","new"], { scope: a => ({ filter: { ...tenantFilter(a), ... }, set: { tenantId: a.tenantId } }) })` | read all in tenant; write department-scoped tasks                    |
| comments    | `allowTableRead("comments")` + `allowTableAction("comments", ["insert","update"], { scope: (a,u) => ({ filter: { ...tenantFilter(a), authorUsername: u }, set: { tenantId: a.tenantId, authorUsername: u } }) })`                                                          | read tenant; write own only                                          |
| documents   | `allowTableRead("documents", { scope: a => ({ filter: { ...tenantFilter(a), classification: { $in: ["public","internal"] } } }) })`                                                                                                                                        | tenant + non-confidential                                            |

### 5.4 member

The narrow contributor role. Tenant-scoped reads via project membership (modeled as: tasks where caller is creator OR assignee, comments where caller is author, projects where caller is owner OR public visibility).

| Resource  | Privilege                                                                                                                                                                                                                                                                                                                                                                                                           | Scope                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| users     | `allowTableRead("users", { scope: a => ({ filter: tenantFilter(a), projection: PROJ_USER_MEMBER }) })`                                                                                                                                                                                                                                                                                                              | tenant + projection limited to `{id, username, email, departmentId}`  |
| projects  | `allowTableRead("projects", { scope: (a,u) => ({ filter: { $or: [{ ...tenantFilter(a), visibility: { $in: ["public","team"] } }, { ownerUsername: u }] } }) })`                                                                                                                                                                                                                                                     | OR of (tenant + visible) and (owned)                                  |
| tasks     | `allowTableRead("tasks", { scope: (a,u) => ({ filter: { ...tenantFilter(a), $or: [{ creatorUsername: u }, { assigneeUsername: u }] }, projection: PROJ_TASK_MEMBER }) })` + `allowTableAction("tasks", ["markDone","markInProgress","new"], { scope: (a,u) => ({ filter: { ...tenantFilter(a), assigneeUsername: u }, set: { tenantId: a.tenantId, creatorUsername: u, assigneeUsername: u, status: "open" } }) })` | read assigned/created; act on assigned; new task auto-assigns to self |
| comments  | `allowTableRead("comments", { scope: a => ({ filter: tenantFilter(a) }) })` + `allowTableAction("comments", ["insert","update","remove"], { scope: (a,u) => ({ filter: { ...tenantFilter(a), authorUsername: u }, set: { tenantId: a.tenantId, authorUsername: u } }) })`                                                                                                                                           | read tenant; write own                                                |
| documents | `allowTableRead("documents", { scope: a => ({ filter: { ...tenantFilter(a), classification: { $ne: "confidential" } } }) })`                                                                                                                                                                                                                                                                                        | tenant + non-confidential                                             |
| auth      | `defineRole().allow("auth", "handover.trigger")`                                                                                                                                                                                                                                                                                                                                                                    | gates custom workflow                                                 |

### 5.5 viewer

Read-only on the tenant with the heaviest projection mask.

| Resource  | Privilege                                                                                                          | Scope                                                                                    |
| --------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| users     | `allowTableRead("users", { scope: a => ({ filter: tenantFilter(a), projection: PROJ_USER_VIEWER }) })`             | only `{id, username, departmentId}` (no email, no secret notes, no password/mfa/account) |
| projects  | `allowTableRead("projects", { scope: a => ({ filter: { ...tenantFilter(a), visibility: { $ne: "private" } } }) })` | tenant + non-private                                                                     |
| tasks     | `allowTableRead("tasks", { scope: a => ({ filter: tenantFilter(a), projection: PROJ_TASK_VIEWER }) })`             | tenant; no `internalNotes`                                                               |
| comments  | `allowTableRead("comments", { scope: a => ({ filter: tenantFilter(a) }) })`                                        |                                                                                          |
| documents | `allowTableRead("documents", { scope: a => ({ filter: { ...tenantFilter(a), classification: "public" } }) })`      | only public                                                                              |

### 5.6 guest

Login only; read own user record (for `/auth/status`).

| Resource | Privilege                                                                                                | Scope                              |
| -------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| users    | `allowTableRead("users", { scope: (a,u) => ({ filter: { username: u }, projection: PROJ_USER_SELF }) })` | self only; `{id, username, email}` |

### 5.7 Field-projection constants

```ts
export const PROJ_USER_ADMIN: TProjection = { "password.history": 0, "mfa.methods": 0 };
export const PROJ_USER_MANAGER: TProjection = {
  password: 0,
  "mfa.value": 0,
  account: 0,
  secretNotes: 0,
};
export const PROJ_USER_MEMBER: TProjection = { id: 1, username: 1, email: 1, departmentId: 1 };
export const PROJ_USER_VIEWER: TProjection = { id: 1, username: 1, departmentId: 1 };
export const PROJ_USER_SELF: TProjection = { id: 1, username: 1, email: 1 };

export const PROJ_TASK_MEMBER: TProjection = { internalNotes: 0 };
export const PROJ_TASK_VIEWER: TProjection = { internalNotes: 0 };

export const WRITEABLE_USER_FIELDS_ADMIN = [
  "email",
  "tenantId",
  "departmentId",
  "secretNotes",
  "account.active",
  "account.locked",
  "mfa.defaultMethod",
  "mfa.autoSend",
];
```

`roles` is NOT writeable via plain PATCH /users — only via `users.assignRoles` action.

### 5.7b Per-role `controls` gating (Uniquery `$with` / `$groupBy` / `$having`)

Each `ArbacDbScope` may carry a `controls?: Record<string, ControlGate>` map.
`AsArbacDbController.validateControls` enforces it on every read endpoint
(`/query`, `/pages`, `/one` where applicable). Per-role gates union additively
across roles (silence wins → allowed).

| Role       | $with  | $groupBy | $having | Notes                                                            |
| ---------- | ------ | -------- | ------- | ---------------------------------------------------------------- |
| superadmin | silent | silent   | silent  | no `controls` map → fully allowed                                |
| admin      | silent | silent   | silent  | no `controls` map → fully allowed                                |
| manager    | silent | silent   | silent  | no `controls` map → fully allowed                                |
| member     | silent | denied   | denied  | `{ $groupBy: false, $having: false }` on all reads               |
| viewer     | denied | denied   | denied  | `{ $with: false, $groupBy: false, $having: false }` on all reads |
| guest      | silent | silent   | silent  | restricted by filter/projection alone                            |

Multi-role union: e.g. `t1_alice` is `[member, viewer]`. Member is silent on
`$with` (allowed); viewer denies it. Union → silence wins → `$with` is allowed.

### 5.8 Cross-role-union test cases

To exercise union semantics, the seed creates:

- `t1_alice` = `[member, viewer]` — member's narrow filter UNION viewer's broad filter must yield viewer's set; projections must be unioned.
- `t1_bob` = `[member]` only — control.
- `t1_carol` = `[manager, viewer]` — manager's narrow write rights + viewer's broad read.
- `t1_dave` = `[admin]` — full tenant.
- `t1_eve` = `[viewer]` — strict viewer.
- `t1_frank` = `[guest]` — login-only.
- `t2_olivia` = `[admin]` — admin of tenant 2 (cross-tenant tests).
- `t2_oscar` = `[member]` — member of tenant 2.
- `_super` = `[superadmin]` (no tenantId — cross-tenant attribute is absent or empty).

---

## 6. Controllers

All db-backed controllers are **empty subclasses** of `AsArbacDbController<typeof Model>` decorated `@TableController(table)` + `@ArbacResource("...")`. Custom actions live as methods on those classes (still relatively lean: a couple of lines wrapping `this.table.*` calls with `scopedFilter()`).

### 6.1 `health.controller.ts`

```ts
@Controller("health")
export class HealthController {
  @Get()
  @Public()
  health(): { ok: true } {
    return { ok: true };
  }

  @Get("protected")
  protected(): { user: string } {
    return { user: useAuth().getCurrentUserId() };
  }

  @Get("admin-only")
  @ArbacResource("health")
  @ArbacAction("admin")
  adminOnly(): { ok: true; user: string } {
    return { ok: true, user: useAuth().getCurrentUserId() };
  }
}
```

### 6.2 `tenants.controller.ts` — empty subclass

```ts
@TableController(tenantsTable)
@ArbacResource("tenants")
export class TenantsController extends AsArbacDbController<typeof Tenant> {}
```

### 6.3 `users.controller.ts` — empty subclass + custom actions

```ts
@TableController(usersTable)
@ArbacResource("users")
export class UsersController extends AsArbacDbController<typeof DemoUser> {
  @Post("actions/assignRoles")
  @DbAction<typeof DemoUser, []>("assignRoles", { ... })
  async assignRoles(@DbActionID() id, @InputForm(AssignRolesForm) form) { ... }

  @Post("actions/lock")
  @DbAction("lock", { ... })
  async lock(@DbActionID() id, @InputForm(LockForm) form) { ... }

  @Post("actions/unlock")
  @DbAction("unlock", { ... })
  async unlock(@DbActionID() id) { ... }
}
```

### 6.4 `departments.controller.ts` — empty subclass

### 6.5 `projects.controller.ts` — empty subclass + handover trigger entry

```ts
@TableController(projectsTable)
@ArbacResource("projects")
export class ProjectsController extends AsArbacDbController<typeof Project> {}
```

(The handover workflow is triggered via `/wf/admin` with `auth.handover.trigger` or via a project-scoped endpoint; design preference: bind to the workflow controller, not the table controller.)

### 6.6 `tasks.controller.ts` — empty subclass + 5 custom actions

```ts
@TableController(tasksTable)
@ArbacResource("tasks")
export class TasksController extends AsArbacDbController<typeof Task> {
  @Post("actions/new")        @DbAction("new", { ... })            @InputForm(NewTaskForm)        async newTask(...) {...}
  @Post("actions/markDone")   @DbAction("markDone", { ... })       async markDone(...) {...}
  @Post("actions/markInProgress") @DbAction("markInProgress", { ... }) async markInProgress(...) {...}
  @Post("actions/archive")    @DbAction("archive", { ... })        async archive(...) {...}
  @Post("actions/assign")     @DbAction("assign", { ... })         @InputForm(AssignTaskForm)     async assign(...) {...}
  @Post("actions/delete")     @DbAction("delete", { ... })         async deleteTask(...) {...}
}
```

Each action body is ~5 lines: `scopedFilter`, `this.table.updateMany`, `if (matchedCount === 0) throw new HttpError(404, ...)`, return `{ ok, message }`. All scope/field gating is done by the base class + `applyAllowedFieldsAndSet` already; the body's only job is the actual mutation.

### 6.7 `comments.controller.ts` — empty subclass

### 6.8 `documents.controller.ts` — empty subclass

### 6.9 `audit.controller.ts` — empty subclass (read-only)

Since the role matrix only grants read on `audit`, the writes are guarded by ARBAC (no role allows write). Writes are inserted internally by an `onWrite`/`onRemove` hook or a custom interceptor — see §7.

### 6.10 `wf-trigger.controller.ts`

Two routes:

- `POST /wf/public` — auth-Public + ARBAC-Public; allow-list = `["auth.login", "auth.recovery", "project.handover"]`. Magic-link resume via `?wfs=<token>`. (Handover resume token uses `?wfs=...` too.)
- `POST /wf/admin` — protected. ARBAC `@ArbacResource("auth") @ArbacAction("admin.invite")`; allow-list = `["auth.invite"]`.

---

## 7. Audit Log (optional behavior to test)

Two ways to populate `audit_log`:

1. **Side-effect at action sites** (chosen for simplicity): each custom action inserts an `AuditEntry` after a successful mutation. Tests assert log rows exist after writes. This keeps the audit path explicit and testable.

2. **Global afterInterceptor** (alternative): a single interceptor hooks every write and records. Skipped to avoid coupling.

The audit table is **read-only via HTTP** — no role has write privilege; writes happen via the `auditTable.insertOne(...)` call inside controllers, bypassing the ARBAC interceptor since they're internal.

---

## 8. Workflows

### 8.1 Bundled (from `@aoothjs/auth-moost`)

- `auth.login` (+ MFA branch)
- `auth.recovery`
- `auth.invite`

Setup via `setupAuthWorkflows({ emailSender, buildMagicLinkUrl, wfStateStore })`.

### 8.2 Custom: `project.handover`

```ts
interface HandoverWfCtx {
  projectId?: string;
  currentOwner?: string;
  targetOwner?: string;
  confirmed?: boolean;
  notified?: boolean;
}

@Injectable("FOR_EVENT")
@Controller()
@Public() // combined: skips auth-moost guard AND arbac for this workflow controller
export class HandoverWorkflow {
  @Workflow("project.handover")
  @WorkflowSchema<HandoverWfCtx>([
    { id: "selectTarget" },
    { id: "confirm" },
    { id: "notify" },
    { id: "commit" },
  ])
  flow(): void {}

  @Step("selectTarget") // expects { projectId, targetOwner }; verifies current user is owner or admin
  @Step("confirm")      // collects boolean confirm flag
  @Step("notify")       // outletEmail to currentOwner; resume via magic link
  @Step("commit")       // updates project.ownerUsername
}
```

Why this workflow exists:

- **Persistent state:** `selectTarget` + `confirm` data must survive through the email-out-and-back resume.
- **Transient state:** after `commit`, the `wf_states` row must be purged.
- **Outlets + email + magic link:** `notify` step writes a magic-link URL.
- **ARBAC gates trigger:** non-owner/non-admin denied at `selectTarget`.

### 8.3 Workflow state store

`AsWfStore` over `wfStatesTable`. Shared across all four workflows. The handle deletion strategy is `consume`/`getAndDelete` for single-use semantics.

---

## 9. Email Sender

Two implementations, selected at boot:

```ts
// console-email-sender.ts (default for `pnpm dev`)
class ConsoleEmailSender implements EmailSender {
  async send(e) {
    console.log("[EMAIL]", e);
  }
}

// capture-email-sender.ts (default in tests)
class CaptureEmailSender implements EmailSender {
  events: AuthEmailEvent[] = [];
  async send(e: AuthEmailEvent) {
    this.events.push(e);
  }
  drain(): AuthEmailEvent[] {
    return this.events.splice(0, this.events.length);
  }
  next(filter?: (e: AuthEmailEvent) => boolean): AuthEmailEvent {
    /* wait until match or timeout */
  }
}
```

`buildAppForTest({ emailSender })` accepts a captured sender so tests can assert email contents.

---

## 10. Environment

```ts
// env.ts
export const ENV = {
  PORT: Number(process.env.PORT ?? 3001),
  DB_PATH: process.env.DB_PATH ?? ":memory:", // tests default to in-memory
  FRONTEND_URL: process.env.FRONTEND_URL ?? "http://localhost:5173",
  JWT_SECRET: process.env.JWT_SECRET ?? "e2e-demo-secret-do-not-use-in-prod",
  ACCESS_TTL_MS: Number(process.env.ACCESS_TTL_MS ?? 60_000 * 60),
  REFRESH_TTL_MS: Number(process.env.REFRESH_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
  LOCKOUT_THRESHOLD: Number(process.env.LOCKOUT_THRESHOLD ?? 3),
  LOCKOUT_DURATION_MS: Number(process.env.LOCKOUT_DURATION_MS ?? 5_000),
  RECOVERY_TTL_MS: Number(process.env.RECOVERY_TTL_MS ?? 60 * 60 * 1000),
  INVITE_TTL_MS: Number(process.env.INVITE_TTL_MS ?? 7 * 24 * 60 * 60 * 1000),
};
```

Tests override env via `buildAppForTest({ overrides })` (or env vars set in `beforeAll`) — never write to `process.env` directly across test files.

---

## 11. App Factory

```ts
// app.ts
export interface BuildAppOptions {
  emailSender?: EmailSender;
  dbPath?: string;
  env?: Partial<typeof ENV>;
}

export async function buildApp(
  opts: BuildAppOptions = {},
): Promise<{ app: Moost; baseUrl: string; close: () => Promise<void> }> {
  // 1. resolve env
  // 2. create DbSpace + sync tables
  // 3. wire AuthCredential, UserService, ArbacUserReader, EmailSender (default = capture in tests)
  // 4. new Moost(); adapter(HTTP).listen(port=0 in tests for ephemeral); adapter(WF)
  // 5. wire DI (AuthCredential/UserService/MoostAuthConfig) + apply authGuardInterceptor + register AuthController; setupAuthWorkflows
  // 6. replace registry for ArbacUserProvider
  // 7. registerControllers(...)
  // 8. app.applyGlobalInterceptors(arbacAuthorizeInterceptor)
  // 9. app.init()
  // 10. arbac.registerRole(...) for all roles
  // returns base URL (with chosen port) + close handle
}
```

`main.ts` calls `buildApp()` with prod-ish defaults; `test/harness.ts` calls it with capture sender and `:memory:` DB.

---

## 12. Seed

`seed.ts` is idempotent and deterministic. Creates:

- 2 tenants: `tenant-a (Acme)`, `tenant-b (Globex)`.
- 3 departments per tenant: `eng`, `ops`, `sales`.
- Users per tenant per role (usernames prefixed by tenant code for clarity in test assertions). One superadmin.
- 5 projects per tenant (mix of `public`, `team`, `private` visibility).
- 20 tasks per tenant, spread across projects and assignees.
- 30 comments per tenant.
- 10 documents per tenant (mix of classifications).

Run via `pnpm db:init` or programmatically by `harness.ts` after `buildApp`.

---

## 13. Implementation Plan (high level)

Phase A — App scaffolding:

1. **Step 1:** scaffold `packages/e2e-demo` (package.json with `"private": true`, tsconfig, vite, atscript.config). Add to `pnpm-workspace.yaml`. No code yet.
2. **Step 2:** write all `.as` models. Run `pnpm gen:atscript` to verify they compile to `.as.d.ts`.
3. **Step 3:** infra wiring (`db.ts`, `aooth.ts`, `wf-store.ts`, `email/*.ts`, `env.ts`). DB sync verified by a one-shot init.
4. **Step 4:** role catalog under `src/roles/`. Per-role file + index. Verified by adding a smoke test that registers them on a `MoostArbac` instance.

- **SIMPLIFY pass** after step 4.

Phase B — App glue:

5. **Step 5:** controllers (`src/controllers/*.ts`). Empty subclasses + custom actions per spec.
6. **Step 6:** `handover.workflow.ts` + `wf-trigger.controller.ts` + `app.ts` factory + `main.ts`. Boots a real Moost app on a port; smoke-check via `curl /health`.
7. **Step 7:** `seed.ts`. Verified by running `pnpm db:init` and inspecting row counts.

- **SIMPLIFY pass** after step 7.

Phase C — Tests:

8. **Step 8:** `test/harness.ts` — `buildAppForTest({ emailSender })`, login helpers (`asAdmin()`, `asMember()`, ...), fetch helper that wires bearer.
9. **Test A:** `auth.spec.ts` (AUTH-\*).
10. **Test B:** workflow tests (`wf-login.spec.ts`, `wf-recovery.spec.ts`, `wf-invite.spec.ts`, `wf-handover.spec.ts`).

- **SIMPLIFY pass.**

11. **Test C:** `arbac-isolation.spec.ts` + `arbac-union.spec.ts`.
12. **Test D:** `arbac-projection.spec.ts` + `arbac-meta.spec.ts`.
13. **Test E:** `arbac-actions.spec.ts` + `arbac-write.spec.ts`.
14. **Test F:** `controls.spec.ts`.

- **SIMPLIFY pass.**

15. **Test G:** `security.spec.ts` (the big one — may split by sub-area).
16. **Test H:** `dx.spec.ts`.

- **SIMPLIFY pass.**

17. **Final:** run full suite. Capture failures, classify as **bug** (library issue) vs **gap** (missing feature) vs **test bug** (assertion wrong). Write a report.

Each step delegated to a subagent with a verbose self-contained prompt and required skill loads.

---

## 14. Decisions Codified

- **No frontend.** All goals are API-shape. Browser added later if requested.
- **In-memory SQLite for tests.** Fast, deterministic, per-test isolation.
- **`vp test`** for the suite (not `vitest` directly).
- **Real Moost app started in-process** on `port=0` per test file (or per `describe`) — actual HTTP fetches, no mocks. Lifespan: one app per test file (boot in `beforeAll`, close in `afterAll`).
- **`Date.now()` not stubbed** by default — TTL-sensitive tests use short TTLs in env overrides (e.g., 2s recovery TTL) and `setTimeout` to cross expiry.
- **Captured email sender** instead of stubbing the outlet — replicates the consumer's wiring more faithfully than mocking lower layers.
- **One spec file per story-group** so failures map cleanly to story IDs.
