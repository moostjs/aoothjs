import { generateTotpSecret } from "@aooth/user";

import type { AppHandle } from "./app";

export interface SeededUser {
  id: string;
  username: string;
  email: string;
  phone?: string;
  password: string;
  /**
   * Set to `_global` (sentinel) for `_super` — the model validator requires a
   * non-empty string, but the superadmin scope deliberately ignores it.
   */
  tenantId: string;
  departmentId?: string;
  roles: string[];
  /** Only present for users seeded with TOTP MFA. */
  totpSecret?: string;
  /** Plaintext backup codes returned by `generateBackupCodes` — only present when seeded. */
  backupCodes?: string[];
  passwordInitial?: boolean;
  /** Access tokens minted at seed time. */
  activeSessionTokens?: string[];
}

export interface SeedFixtures {
  tenants: {
    "tenant-a": string;
    "tenant-b": string;
  };
  departments: {
    "tenant-a": { eng: string; ops: string; sales: string };
    "tenant-b": { eng: string; ops: string; sales: string };
  };
  users: {
    t1_alice: SeededUser;
    t1_bob: SeededUser;
    t1_carol: SeededUser;
    t1_dave: SeededUser;
    t1_eve: SeededUser;
    t1_frank: SeededUser;
    t1_grace: SeededUser;
    t1_henry: SeededUser;
    t1_ivy: SeededUser;
    t1_jack: SeededUser;
    t1_kate: SeededUser;
    t1_locked: SeededUser;
    t1_multi_mfa: SeededUser;
    t1_pending: SeededUser;
    t1_redeemed: SeededUser;
    t1_active_sessions: SeededUser;
    t1_terms_old: SeededUser;
    t1_profile_incomplete: SeededUser;
    t1_two_tenants: SeededUser;
    /** Parallel `tenant-b` row sharing email with `t1_two_tenants`. */
    t2_two_tenants: SeededUser;
    _admin_inviter: SeededUser;
    t2_olivia: SeededUser;
    t2_oscar: SeededUser;
    _super: SeededUser;
  };
  projects: {
    "proj-a-1": string;
    "proj-a-2": string;
    "proj-a-3": string;
    "proj-a-4": string;
    "proj-a-5": string;
    "proj-b-1": string;
    "proj-b-2": string;
    "proj-b-3": string;
    "proj-b-4": string;
    "proj-b-5": string;
  };
  tasks: { tenantA: string[]; tenantB: string[] };
  comments: { tenantA: string[]; tenantB: string[] };
  documents: { tenantA: string[]; tenantB: string[] };
}

const PASSWORD = "Password1!";

/** Two seeded users (`t1_two_tenants` + `t2_two_tenants`) share this email
 * so the tenant-select variant can resolve it to both rows. */
export const TWO_TENANTS_SHARED_EMAIL = "two_tenants@shared.test";

interface UserSpec {
  handle: keyof SeedFixtures["users"];
  username: string;
  email: string;
  tenantId: string;
  departmentId?: string;
  roles: string[];
  totp?: boolean;
  /** Enroll + confirm `email` MFA on `spec.email`. */
  mfaEmail?: boolean;
  /** Enroll + confirm `sms` MFA on the provided phone; persisted on `users.phone`. */
  mfaSms?: { phone: string };
  /** Generate 10 backup codes — requires `totp` so the `useBackupCode` MFA action is reachable. */
  backupCodes?: boolean;
  /** Insert with `password.isInitial = true` to exercise the forced-password-change guard. */
  passwordInitial?: boolean;
  /** Insert with `account.locked = true`. */
  locked?: boolean;
  /** Insert with `account.active = false, pendingInvitation = true`. */
  pendingInvitation?: boolean;
  /** Override `mfa.defaultMethod` after enrolment (only honored if that method is present). */
  defaultMfaMethod?: string;
  /** Mint N access tokens via `authCredential.issue` post-seed (returned on `activeSessionTokens`). */
  activeSessions?: number;
}

export async function seedAll(handle: AppHandle): Promise<SeedFixtures> {
  const { appDb } = handle;
  const { tables } = appDb;

  // Idempotency guard for `pnpm db:init` against an existing file-backed DB.
  // Tests boot a fresh `:memory:` per run so this branch is rarely hit; we
  // reject loudly rather than risk handing back a half-populated fixture set.
  if ((await tables.users.count({ filter: {} })) > 0) {
    throw new Error(
      "seedAll: users table is non-empty. Delete the DB file (e.g. `rm e2e-demo.sqlite`) and re-run.",
    );
  }

  const tenantAId = await insertReturningId(
    tables.tenants.insertOne({ name: "Acme", plan: "pro" }),
  );
  const tenantBId = await insertReturningId(
    tables.tenants.insertOne({ name: "Globex", plan: "enterprise" }),
  );

  // Synthetic sentinel tenant so `_super` (`tenantId: '_global'`) satisfies
  // the FK declared in `user.as`. The superadmin role's scope is `none`, so
  // this row is never queried by tenant-scoped business logic; it exists
  // purely to keep PRAGMA foreign_keys happy on insert.
  await tables.tenants.insertOne({ id: "_global", name: "_global", plan: "free" } as never);

  const deptA = await seedDepartments(handle, tenantAId);
  const deptB = await seedDepartments(handle, tenantBId);

  const userSpecs: UserSpec[] = [
    {
      handle: "t1_alice",
      username: "t1_alice",
      email: "alice@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member", "viewer"],
    },
    {
      handle: "t1_bob",
      username: "t1_bob",
      email: "bob@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
    },
    {
      handle: "t1_carol",
      username: "t1_carol",
      email: "carol@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.ops,
      roles: ["manager", "viewer"],
    },
    {
      handle: "t1_dave",
      username: "t1_dave",
      email: "dave@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["admin"],
    },
    {
      handle: "t1_eve",
      username: "t1_eve",
      email: "eve@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.sales,
      roles: ["viewer"],
    },
    {
      handle: "t1_frank",
      username: "t1_frank",
      email: "frank@acme.test",
      tenantId: tenantAId,
      roles: ["guest"],
    },
    {
      handle: "t1_grace",
      username: "t1_grace",
      email: "grace@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.ops,
      roles: ["member"],
      totp: true,
    },
    {
      handle: "t1_henry",
      username: "t1_henry",
      email: "henry@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
      mfaEmail: true,
    },
    {
      handle: "t1_ivy",
      username: "t1_ivy",
      email: "ivy@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.ops,
      roles: ["member"],
      mfaSms: { phone: "+15555550101" },
    },
    {
      handle: "t1_jack",
      username: "t1_jack",
      email: "jack@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.sales,
      roles: ["member"],
      passwordInitial: true,
    },
    {
      handle: "t1_kate",
      username: "t1_kate",
      email: "kate@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
      totp: true,
      backupCodes: true,
    },
    {
      handle: "t1_locked",
      username: "t1_locked",
      email: "locked@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
      locked: true,
    },
    {
      handle: "t1_multi_mfa",
      username: "t1_multi_mfa",
      email: "t1_multi_mfa@example.com",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
      totp: true,
      mfaEmail: true,
      mfaSms: { phone: "+15555550110" },
      defaultMfaMethod: "totp",
    },
    {
      // Pending invitee — MUST NOT appear in any login-workflow testCreds
      // (pending users can't log in); drives reInvite/cancelInvite paths.
      // Invite workflows look up by EMAIL via UserService.getUser which
      // matches username → seed username=email so the lookup resolves.
      handle: "t1_pending",
      username: "t1_pending@example.com",
      email: "t1_pending@example.com",
      tenantId: tenantAId,
      roles: ["member"],
      pendingInvitation: true,
    },
    {
      handle: "t1_redeemed",
      username: "t1_redeemed@example.com",
      email: "t1_redeemed@example.com",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
    },
    {
      handle: "t1_active_sessions",
      username: "t1_active_sessions",
      email: "active_sessions@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
      activeSessions: 2,
    },
    // t1_terms_old / t1_profile_incomplete: no DB column carries the state
    // today — the variant-config layer (PR-D) injects ctx values at runtime.
    {
      handle: "t1_terms_old",
      username: "t1_terms_old",
      email: "terms_old@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
    },
    {
      handle: "t1_profile_incomplete",
      username: "t1_profile_incomplete",
      email: "profile_incomplete@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
    },
    {
      handle: "t1_two_tenants",
      username: "t1_two_tenants",
      email: TWO_TENANTS_SHARED_EMAIL,
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["member"],
    },
    {
      // `_super` lacks `auth.invite/start` (scope is `none` but its allow-list
      // omits the resource), so invite stories need a real `admin` user.
      handle: "_admin_inviter",
      username: "_admin_inviter",
      email: "admin_inviter@acme.test",
      tenantId: tenantAId,
      departmentId: deptA.eng,
      roles: ["admin"],
    },
    {
      handle: "t2_olivia",
      username: "t2_olivia",
      email: "olivia@globex.test",
      tenantId: tenantBId,
      departmentId: deptB.eng,
      roles: ["admin"],
    },
    {
      handle: "t2_two_tenants",
      username: "t2_two_tenants",
      email: TWO_TENANTS_SHARED_EMAIL,
      tenantId: tenantBId,
      departmentId: deptB.eng,
      roles: ["member"],
    },
    {
      handle: "t2_oscar",
      username: "t2_oscar",
      email: "oscar@globex.test",
      tenantId: tenantBId,
      departmentId: deptB.eng,
      roles: ["member"],
    },
    // `_super` is the cross-tenant superadmin. The role's scope is `none`
    // (universe), so the value doesn't drive ARBAC; we use the `_global`
    // sentinel because the schema validator rejects empty strings on a
    // `@meta.required` field.
    {
      handle: "_super",
      username: "_super",
      email: "super@aoothjs.test",
      tenantId: "_global",
      roles: ["superadmin"],
    },
  ];

  const users = {} as SeedFixtures["users"];
  for (const spec of userSpecs) {
    users[spec.handle] = await seedUser(handle, spec);
  }

  const projects = await seedProjects(handle, {
    tenantAId,
    tenantBId,
    deptA,
    deptB,
  });

  const projIdsA = [
    projects["proj-a-1"],
    projects["proj-a-2"],
    projects["proj-a-3"],
    projects["proj-a-4"],
    projects["proj-a-5"],
  ];
  const projIdsB = [
    projects["proj-b-1"],
    projects["proj-b-2"],
    projects["proj-b-3"],
    projects["proj-b-4"],
    projects["proj-b-5"],
  ];

  const tasks = {
    tenantA: await seedTasks(handle, {
      tenantId: tenantAId,
      projectIds: projIdsA,
      creators: ["t1_dave", "t1_carol", "t1_alice", "t1_bob", "t1_eve"],
      memberAssignee: "t1_bob",
      otherAssignees: ["t1_alice", "t1_carol", "t1_eve"],
    }),
    tenantB: await seedTasks(handle, {
      tenantId: tenantBId,
      projectIds: projIdsB,
      creators: ["t2_olivia", "t2_oscar"],
      memberAssignee: "t2_oscar",
      otherAssignees: ["t2_olivia"],
    }),
  };

  const comments = {
    tenantA: await seedComments(handle, {
      tenantId: tenantAId,
      taskIds: tasks.tenantA,
      authors: ["t1_alice", "t1_bob", "t1_carol", "t1_dave", "t1_eve"],
    }),
    tenantB: await seedComments(handle, {
      tenantId: tenantBId,
      taskIds: tasks.tenantB,
      authors: ["t2_olivia", "t2_oscar"],
    }),
  };

  const documents = {
    tenantA: await seedDocuments(handle, {
      tenantId: tenantAId,
      projectIds: projIdsA,
      owners: ["t1_alice", "t1_bob", "t1_carol", "t1_dave", "t1_eve"],
    }),
    tenantB: await seedDocuments(handle, {
      tenantId: tenantBId,
      projectIds: projIdsB,
      owners: ["t2_olivia", "t2_oscar"],
    }),
  };

  return {
    tenants: { "tenant-a": tenantAId, "tenant-b": tenantBId },
    departments: { "tenant-a": deptA, "tenant-b": deptB },
    users,
    projects,
    tasks,
    comments,
    documents,
  };
}

async function seedDepartments(
  handle: AppHandle,
  tenantId: string,
): Promise<{ eng: string; ops: string; sales: string }> {
  const { tables } = handle.appDb;
  // Sequential — better-sqlite3 rejects concurrent transactions.
  const eng = await insertReturningId(
    tables.departments.insertOne({ tenantId, name: "Engineering" }),
  );
  const ops = await insertReturningId(
    tables.departments.insertOne({ tenantId, name: "Operations" }),
  );
  const sales = await insertReturningId(tables.departments.insertOne({ tenantId, name: "Sales" }));
  return { eng, ops, sales };
}

/**
 * Insert a fully-formed credential record directly. Bypasses
 * `userService.createUser` (which only knows the base credential shape and
 * cannot carry tenant/department/email/roles for our extended `DemoUser`).
 * MFA enrolment still goes through the service so confirmed-method bookkeeping
 * stays consistent with the live login flow.
 */
async function seedUser(handle: AppHandle, spec: UserSpec): Promise<SeededUser> {
  const { appDb, aooth } = handle;
  const hash = await aooth.userService.getPasswordHasher().hash(PASSWORD);
  const now = Date.now();
  const phone = spec.mfaSms?.phone;

  const insert = await appDb.tables.users.insertOne({
    username: spec.username,
    email: spec.email,
    phone,
    tenantId: spec.tenantId,
    departmentId: spec.departmentId,
    roles: spec.roles,
    password: { hash, history: [], lastChanged: now, isInitial: spec.passwordInitial ?? false },
    account: {
      active: !spec.pendingInvitation,
      locked: spec.locked ?? false,
      lockReason: spec.locked ? "seed: pre-locked" : "",
      lockEnds: 0,
      failedLoginAttempts: 0,
      lastLogin: 0,
      ...(spec.pendingInvitation && { pendingInvitation: true }),
    },
    mfa: { methods: [], defaultMethod: "", autoSend: false },
  } as never);
  const id = (insert as { insertedId: unknown }).insertedId;
  if (typeof id !== "string") {
    throw new Error(`seedUser ${spec.username}: expected string insertedId, got ${typeof id}`);
  }

  let totpSecret: string | undefined;
  if (spec.totp) {
    totpSecret = generateTotpSecret();
    await aooth.userService.addMfaMethod(spec.username, {
      name: "totp",
      confirmed: false,
      value: totpSecret,
    });
    await aooth.userService.confirmMfaMethod(spec.username, "totp");
    // Surfaced for the dev operator running pnpm run dev — copy into an
    // authenticator app to drive the TOTP MFA branch from the UI.
    console.log(`[seed] ${spec.username} totp secret: ${totpSecret}`);
  }

  if (spec.mfaEmail) {
    await aooth.userService.addMfaMethod(spec.username, {
      name: "email",
      confirmed: false,
      value: spec.email,
    });
    await aooth.userService.confirmMfaMethod(spec.username, "email");
  }

  if (spec.mfaSms) {
    await aooth.userService.addMfaMethod(spec.username, {
      name: "sms",
      confirmed: false,
      value: spec.mfaSms.phone,
    });
    await aooth.userService.confirmMfaMethod(spec.username, "sms");
  }

  // Backup codes must go in AFTER TOTP enrolment — the `useBackupCode` MFA
  // action only surfaces from inside an MFA step, which requires at least
  // one confirmed factor.
  let backupCodes: string[] | undefined;
  if (spec.backupCodes) {
    backupCodes = await aooth.userService.generateBackupCodes(spec.username, 10);
    console.log(`[seed] ${spec.username} backup codes (plaintext): ${backupCodes.join(" ")}`);
    // Surface to /__test/backup-codes/:username so Playwright specs can
    // submit a known-good code (stored form is hashed; the seed is the only
    // place plaintext exists).
    /* eslint-disable no-underscore-dangle -- intentional globalThis slot */
    const g = globalThis as { __aoothE2eBackupCodes?: Map<string, string[]> };
    g.__aoothE2eBackupCodes?.set(spec.username, [...backupCodes]);
    /* eslint-enable no-underscore-dangle */
  }

  if (spec.defaultMfaMethod) {
    await aooth.userService.setDefaultMfaMethod(spec.username, spec.defaultMfaMethod);
  }

  let activeSessionTokens: string[] | undefined;
  if (spec.activeSessions) {
    activeSessionTokens = [];
    for (let i = 0; i < spec.activeSessions; i++) {
      const issued = await aooth.authCredential.issue(spec.username);
      activeSessionTokens.push(issued.accessToken);
    }
    console.log(`[seed] ${spec.username} active sessions: ${activeSessionTokens.length}`);
  }

  return {
    id,
    username: spec.username,
    email: spec.email,
    phone,
    password: PASSWORD,
    tenantId: spec.tenantId,
    departmentId: spec.departmentId,
    roles: spec.roles,
    totpSecret,
    backupCodes,
    passwordInitial: spec.passwordInitial,
    activeSessionTokens,
  };
}

interface ProjectSeedDeps {
  tenantAId: string;
  tenantBId: string;
  deptA: { eng: string; ops: string; sales: string };
  deptB: { eng: string; ops: string; sales: string };
}

async function seedProjects(
  handle: AppHandle,
  d: ProjectSeedDeps,
): Promise<SeedFixtures["projects"]> {
  const { tables } = handle.appDb;
  const projectSpecs: Array<{
    handle: keyof SeedFixtures["projects"];
    name: string;
    tenantId: string;
    departmentId?: string;
    ownerUsername: string;
    visibility: "public" | "team" | "private";
    secretBudget?: number;
  }> = [
    {
      handle: "proj-a-1",
      name: "Acme Public Site",
      tenantId: d.tenantAId,
      departmentId: d.deptA.eng,
      ownerUsername: "t1_dave",
      visibility: "public",
    },
    {
      handle: "proj-a-2",
      name: "Acme Ops Dashboard",
      tenantId: d.tenantAId,
      departmentId: d.deptA.ops,
      ownerUsername: "t1_carol",
      visibility: "team",
    },
    {
      handle: "proj-a-3",
      name: "Acme Secret Lab",
      tenantId: d.tenantAId,
      departmentId: d.deptA.eng,
      ownerUsername: "t1_dave",
      visibility: "private",
    },
    {
      handle: "proj-a-4",
      name: "Acme Bob Side Project",
      tenantId: d.tenantAId,
      departmentId: d.deptA.eng,
      ownerUsername: "t1_bob",
      visibility: "team",
    },
    {
      handle: "proj-a-5",
      name: "Acme Alice Public",
      tenantId: d.tenantAId,
      departmentId: d.deptA.eng,
      ownerUsername: "t1_alice",
      visibility: "public",
      secretBudget: 100000,
    },
    {
      handle: "proj-b-1",
      name: "Globex Public Portal",
      tenantId: d.tenantBId,
      departmentId: d.deptB.eng,
      ownerUsername: "t2_olivia",
      visibility: "public",
    },
    {
      handle: "proj-b-2",
      name: "Globex Internal Tools",
      tenantId: d.tenantBId,
      departmentId: d.deptB.eng,
      ownerUsername: "t2_olivia",
      visibility: "team",
    },
    {
      handle: "proj-b-3",
      name: "Globex Skunkworks",
      tenantId: d.tenantBId,
      departmentId: d.deptB.eng,
      ownerUsername: "t2_olivia",
      visibility: "private",
    },
    {
      handle: "proj-b-4",
      name: "Globex Oscar Hack",
      tenantId: d.tenantBId,
      departmentId: d.deptB.eng,
      ownerUsername: "t2_oscar",
      visibility: "team",
    },
    {
      handle: "proj-b-5",
      name: "Globex Oscar Public",
      tenantId: d.tenantBId,
      departmentId: d.deptB.eng,
      ownerUsername: "t2_oscar",
      visibility: "public",
    },
  ];

  const out = {} as SeedFixtures["projects"];
  for (const spec of projectSpecs) {
    out[spec.handle] = await insertReturningId(
      tables.projects.insertOne({
        tenantId: spec.tenantId,
        departmentId: spec.departmentId,
        name: spec.name,
        ownerUsername: spec.ownerUsername,
        visibility: spec.visibility,
        secretBudget: spec.secretBudget,
      }),
    );
  }
  return out;
}

interface TaskSeedSpec {
  tenantId: string;
  projectIds: string[];
  creators: string[];
  /** Username guaranteed at least 5 assignments — supports member-scope tests. */
  memberAssignee: string;
  otherAssignees: string[];
}

async function seedTasks(handle: AppHandle, spec: TaskSeedSpec): Promise<string[]> {
  const { tables } = handle.appDb;
  const ids: string[] = [];
  for (let i = 0; i < 20; i++) {
    const status: "open" | "in_progress" | "done" =
      i < 10 ? "open" : i < 15 ? "in_progress" : "done";
    // First 5 tasks (indices 0..4) go to the member-assignee for member-scope coverage.
    const assignee =
      i < 5 ? spec.memberAssignee : spec.otherAssignees[(i - 5) % spec.otherAssignees.length];
    const creator = spec.creators[i % spec.creators.length];
    const projectId = spec.projectIds[i % spec.projectIds.length];
    // Tasks 0 and 10 carry internalNotes for projection tests.
    const internalNotes = i === 0 || i === 10 ? "Confidential project memo" : undefined;

    const id = await insertReturningId(
      tables.tasks.insertOne({
        tenantId: spec.tenantId,
        projectId,
        title: `Task ${i + 1}`,
        description: `Seeded task ${i + 1} in tenant ${spec.tenantId}`,
        creatorUsername: creator,
        assigneeUsername: assignee,
        status,
        priority: i % 3 === 0 ? "high" : i % 3 === 1 ? "medium" : "low",
        internalNotes,
      }),
    );
    ids.push(id);
  }
  return ids;
}

interface CommentSeedSpec {
  tenantId: string;
  taskIds: string[];
  authors: string[];
}

async function seedComments(handle: AppHandle, spec: CommentSeedSpec): Promise<string[]> {
  const { tables } = handle.appDb;
  const ids: string[] = [];
  for (let i = 0; i < 30; i++) {
    const id = await insertReturningId(
      tables.comments.insertOne({
        tenantId: spec.tenantId,
        taskId: spec.taskIds[i % spec.taskIds.length],
        authorUsername: spec.authors[i % spec.authors.length],
        body: `Comment ${i + 1} in tenant ${spec.tenantId}`,
      }),
    );
    ids.push(id);
  }
  return ids;
}

interface DocumentSeedSpec {
  tenantId: string;
  projectIds: string[];
  owners: string[];
}

async function seedDocuments(handle: AppHandle, spec: DocumentSeedSpec): Promise<string[]> {
  const { tables } = handle.appDb;
  const ids: string[] = [];
  for (let i = 0; i < 10; i++) {
    const classification: "public" | "internal" | "confidential" =
      i < 4 ? "public" : i < 8 ? "internal" : "confidential";
    const id = await insertReturningId(
      tables.documents.insertOne({
        tenantId: spec.tenantId,
        projectId: spec.projectIds[i % spec.projectIds.length],
        title: `Doc ${i + 1}`,
        body: `Body of doc ${i + 1}`,
        classification,
        ownerUsername: spec.owners[i % spec.owners.length],
      }),
    );
    ids.push(id);
  }
  return ids;
}

async function insertReturningId(promise: Promise<{ insertedId: unknown }>): Promise<string> {
  const { insertedId } = await promise;
  if (typeof insertedId !== "string") {
    throw new Error(`Expected string insertedId, got ${typeof insertedId}`);
  }
  return insertedId;
}
