import { buildApp } from "../app";
import { seedAll } from "../seed";

async function main(): Promise<void> {
  const handle = await buildApp({ dbPath: ":memory:", port: 0 });
  const fixtures = await seedAll(handle);
  const { tables } = handle.appDb;

  const checks: Array<[string, number, number]> = [
    // 2 real + 1 synthetic `_global` sentinel for the `_super` FK.
    ["tenants", await tables.tenants.count({ filter: {} }), 3],
    ["departments", await tables.departments.count({ filter: {} }), 6],
    ["users", await tables.users.count({ filter: {} }), 10],
    ["projects", await tables.projects.count({ filter: {} }), 10],
    ["tasks", await tables.tasks.count({ filter: {} }), 40],
    ["comments", await tables.comments.count({ filter: {} }), 60],
    ["documents", await tables.documents.count({ filter: {} }), 20],
  ];

  for (const [name, actual, expected] of checks) {
    if (actual !== expected) {
      throw new Error(`expected ${expected} ${name}, got ${actual}`);
    }
    // biome-ignore lint/suspicious/noConsole: probe script
    console.log(`[probe-seed] ${name}: ${actual} OK`);
  }

  // t1_grace must have a confirmed totp MFA method.
  const grace = await handle.aooth.userStore.findByUsername("t1_grace");
  if (!grace) throw new Error("t1_grace not found");
  const totp = grace.mfa.methods.find((m) => m.name === "totp");
  if (!totp) throw new Error("t1_grace missing totp MFA method");
  if (!totp.confirmed) throw new Error("t1_grace totp MFA not confirmed");
  if (!fixtures.users.t1_grace.totpSecret) {
    throw new Error("fixtures.users.t1_grace.totpSecret missing");
  }
  // biome-ignore lint/suspicious/noConsole: probe script
  console.log("[probe-seed] t1_grace totp confirmed OK");

  // t1_alice must carry both `member` and `viewer` roles for UNION tests.
  const alice = await handle.aooth.userStore.findByUsername("t1_alice");
  if (!alice) throw new Error("t1_alice not found");
  const roles = (alice as unknown as { roles?: string[] }).roles ?? [];
  if (!roles.includes("member") || !roles.includes("viewer")) {
    throw new Error(`t1_alice roles missing member/viewer: ${JSON.stringify(roles)}`);
  }
  // biome-ignore lint/suspicious/noConsole: probe script
  console.log(`[probe-seed] t1_alice roles=${JSON.stringify(roles)} OK`);

  // Each tenant should have at least one private project (exact: 1 per tenant).
  const privateA = await tables.projects.count({
    filter: { tenantId: fixtures.tenants["tenant-a"], visibility: "private" },
  });
  const privateB = await tables.projects.count({
    filter: { tenantId: fixtures.tenants["tenant-b"], visibility: "private" },
  });
  if (privateA !== 1) throw new Error(`tenant-a private projects: expected 1, got ${privateA}`);
  if (privateB !== 1) throw new Error(`tenant-b private projects: expected 1, got ${privateB}`);
  // biome-ignore lint/suspicious/noConsole: probe script
  console.log("[probe-seed] private projects per tenant: 1/1 OK");

  // _super uses a sentinel (model validator rejects empty strings). Superadmin
  // scope ignores tenantId regardless.
  if (fixtures.users._super.tenantId !== "_global") {
    throw new Error(`_super.tenantId expected '_global', got '${fixtures.users._super.tenantId}'`);
  }
  // biome-ignore lint/suspicious/noConsole: probe script
  console.log("[probe-seed] _super.tenantId='_global' OK");

  await handle.close();
  // biome-ignore lint/suspicious/noConsole: probe script
  console.log("[probe-seed] all assertions passed");
}

main().catch((err) => {
  // biome-ignore lint/suspicious/noConsole: probe script
  console.error("[probe-seed] FAILED", err);
  process.exit(1);
});
