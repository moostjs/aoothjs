import { Arbac } from "@aoothjs/arbac-core";

import { type ArbacDbScope, type UserAttrs, allRoles } from "../roles";

interface ProbeCase {
  label: string;
  roles: string[];
  attrs: UserAttrs;
  userId: string;
  resource: string;
  action: string;
  expectAllowed: boolean;
  expect?: (scopes: ArbacDbScope[] | undefined) => string | null;
}

const fmtScopes = (scopes: ArbacDbScope[] | undefined): string =>
  !scopes || scopes.length === 0 ? "[]" : JSON.stringify(scopes);

const filterOf = (scopes: ArbacDbScope[] | undefined): Record<string, unknown> | undefined =>
  scopes?.[0]?.filter as Record<string, unknown> | undefined;

const setOf = (scopes: ArbacDbScope[] | undefined): Record<string, unknown> | undefined =>
  scopes?.[0]?.set;

async function main(): Promise<void> {
  const arbac = new Arbac<UserAttrs, ArbacDbScope>();
  for (const role of allRoles) {
    arbac.registerRole(role);
  }

  const cases: ProbeCase[] = [
    {
      label: "superadmin / tenants.update",
      roles: ["superadmin"],
      attrs: { tenantId: "" },
      userId: "_super",
      resource: "tenants",
      action: "update",
      expectAllowed: true,
      expect: (scopes) =>
        scopes && scopes.length === 0 ? null : `expected no scopes, got ${fmtScopes(scopes)}`,
    },
    {
      label: "admin / tasks.query (tenant A)",
      roles: ["admin"],
      attrs: { tenantId: "A" },
      userId: "t1_dave",
      resource: "tasks",
      action: "query",
      expectAllowed: true,
      expect: (scopes) => {
        const f = filterOf(scopes);
        return f?.tenantId === "A"
          ? null
          : `expected filter.tenantId='A', got ${JSON.stringify(f)}`;
      },
    },
    {
      label: "admin / tasks.new (forces tenantId+creatorUsername)",
      roles: ["admin"],
      attrs: { tenantId: "A" },
      userId: "t1_dave",
      resource: "tasks",
      action: "new",
      expectAllowed: true,
      expect: (scopes) => {
        const set = setOf(scopes);
        return set?.tenantId === "A" && set?.creatorUsername === "t1_dave"
          ? null
          : `expected set.{tenantId,creatorUsername}, got ${JSON.stringify(set)}`;
      },
    },
    {
      label: "admin / users.update (allowedFields whitelist excludes 'roles')",
      roles: ["admin"],
      attrs: { tenantId: "A" },
      userId: "t1_dave",
      resource: "users",
      action: "update",
      expectAllowed: true,
      expect: (scopes) => {
        const allowed = scopes?.[0]?.allowedFields;
        if (!Array.isArray(allowed)) return `expected allowedFields array, got ${typeof allowed}`;
        if (allowed.includes("roles")) return `'roles' must NOT be in allowedFields`;
        return allowed.includes("email") ? null : `expected 'email' to be writeable`;
      },
    },
    {
      label: "admin / auth.invite.start",
      roles: ["admin"],
      attrs: { tenantId: "A" },
      userId: "t1_dave",
      resource: "auth.invite",
      action: "start",
      expectAllowed: true,
    },
    {
      label: "manager / tasks.query (tenant-wide read)",
      roles: ["manager"],
      attrs: { tenantId: "A", departmentId: "eng" },
      userId: "t1_mike",
      resource: "tasks",
      action: "query",
      expectAllowed: true,
      expect: (scopes) => {
        const f = filterOf(scopes);
        return f?.tenantId === "A" && f.departmentId === undefined
          ? null
          : `expected tenant-only filter, got ${JSON.stringify(f)}`;
      },
    },
    {
      label: "manager / tasks.update (department-scoped)",
      roles: ["manager"],
      attrs: { tenantId: "A", departmentId: "eng" },
      userId: "t1_mike",
      resource: "tasks",
      action: "update",
      expectAllowed: true,
      expect: (scopes) => {
        const f = filterOf(scopes);
        return f?.tenantId === "A" && f.departmentId === "eng"
          ? null
          : `expected tenant+department filter, got ${JSON.stringify(f)}`;
      },
    },
    {
      label: "member / projects.query ($or: visible OR owned)",
      roles: ["member"],
      attrs: { tenantId: "A" },
      userId: "t1_bob",
      resource: "projects",
      action: "query",
      expectAllowed: true,
      expect: (scopes) => {
        const f = filterOf(scopes);
        return Array.isArray(f?.$or) && (f.$or as unknown[]).length === 2
          ? null
          : `expected $or with 2 branches, got ${JSON.stringify(f)}`;
      },
    },
    {
      label: "member / tasks.new (auto-assign self)",
      roles: ["member"],
      attrs: { tenantId: "A" },
      userId: "t1_bob",
      resource: "tasks",
      action: "new",
      expectAllowed: true,
      expect: (scopes) => {
        const set = setOf(scopes);
        return set?.assigneeUsername === "t1_bob" &&
          set.creatorUsername === "t1_bob" &&
          set.status === "open"
          ? null
          : `expected self-assignee+creator+open, got ${JSON.stringify(set)}`;
      },
    },
    {
      label: "member / tasks.delete (denied)",
      roles: ["member"],
      attrs: { tenantId: "A" },
      userId: "t1_bob",
      resource: "tasks",
      action: "delete",
      expectAllowed: false,
    },
    {
      label: "member / auth.handover.trigger",
      roles: ["member"],
      attrs: { tenantId: "A" },
      userId: "t1_bob",
      resource: "auth",
      action: "handover.trigger",
      expectAllowed: true,
    },
    {
      label: "viewer / tasks.query (projection)",
      roles: ["viewer"],
      attrs: { tenantId: "A" },
      userId: "t1_eve",
      resource: "tasks",
      action: "query",
      expectAllowed: true,
      expect: (scopes) => {
        const proj = scopes?.[0]?.projection;
        return proj && (proj as Record<string, 0 | 1>).internalNotes === 0
          ? null
          : `expected projection.internalNotes=0, got ${JSON.stringify(proj)}`;
      },
    },
    {
      label: "viewer / tasks.remove (denied)",
      roles: ["viewer"],
      attrs: { tenantId: "A" },
      userId: "t1_eve",
      resource: "tasks",
      action: "remove",
      expectAllowed: false,
    },
    {
      label: "viewer / documents.query (public-only filter)",
      roles: ["viewer"],
      attrs: { tenantId: "A" },
      userId: "t1_eve",
      resource: "documents",
      action: "query",
      expectAllowed: true,
      expect: (scopes) => {
        const f = filterOf(scopes);
        return f?.classification === "public"
          ? null
          : `expected classification='public', got ${JSON.stringify(f)}`;
      },
    },
    {
      label: "guest / users.one (self-only)",
      roles: ["guest"],
      attrs: { tenantId: "A" },
      userId: "t1_frank",
      resource: "users",
      action: "one",
      expectAllowed: true,
      expect: (scopes) => {
        const f = filterOf(scopes);
        return f?.username === "t1_frank"
          ? null
          : `expected username='t1_frank', got ${JSON.stringify(f)}`;
      },
    },
    {
      label: "guest / tasks.query (denied)",
      roles: ["guest"],
      attrs: { tenantId: "A" },
      userId: "t1_frank",
      resource: "tasks",
      action: "query",
      expectAllowed: false,
    },
    {
      label: "[member,viewer] union / projects.query (filter union — UNION-01)",
      roles: ["member", "viewer"],
      attrs: { tenantId: "A" },
      userId: "t1_alice",
      resource: "projects",
      action: "query",
      expectAllowed: true,
      expect: (scopes) =>
        scopes && scopes.length === 2
          ? null
          : `expected 2 scopes (member + viewer), got ${scopes?.length ?? 0}`,
    },
  ];

  let failed = 0;
  for (const c of cases) {
    const res = await arbac.evaluate(
      { resource: c.resource, action: c.action },
      { id: c.userId, roles: c.roles, attrs: c.attrs },
    );
    const allowedOk = res.allowed === c.expectAllowed;
    const expectMsg = c.expect && res.allowed ? c.expect(res.scopes) : null;
    const ok = allowedOk && !expectMsg;
    // biome-ignore lint/suspicious/noConsole: smoke probe
    console.log(
      `[${ok ? "PASS" : "FAIL"}] ${c.label} → allowed=${res.allowed} scopes=${fmtScopes(res.scopes)}`,
    );
    if (!allowedOk) {
      failed++;
      // biome-ignore lint/suspicious/noConsole: smoke probe
      console.error(`       expected allowed=${c.expectAllowed}, got allowed=${res.allowed}`);
    } else if (expectMsg) {
      failed++;
      // biome-ignore lint/suspicious/noConsole: smoke probe
      console.error(`       ${expectMsg}`);
    }
  }

  if (failed > 0) {
    throw new Error(`${failed} probe case(s) failed`);
  }
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log(`[probe-roles] OK — ${cases.length} cases passed`);
}

main().catch((err) => {
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.error("[probe-roles] FAILED", err);
  process.exit(1);
});
