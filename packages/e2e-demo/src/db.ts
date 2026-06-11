import { type AtscriptDbTable, DbSpace } from "@atscript/db";
import { syncSchema } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";

import { AuditEntry } from "./models/audit.as";
import { DemoAuthCode } from "./models/auth-code.as";
import { DemoAuthCredential } from "./models/auth-credential.as";
import { DemoDynamicClient } from "./models/dynamic-client.as";
import { DemoPendingAuthorization } from "./models/pending-authorization.as";
import { Comment } from "./models/comment.as";
import { Department } from "./models/department.as";
import { Document } from "./models/document.as";
import { DemoFederatedIdentity } from "./models/federated-identity.as";
import { Project } from "./models/project.as";
import { Task } from "./models/task.as";
import { Tenant } from "./models/tenant.as";
import { DemoUser } from "./models/user.as";
import { DemoWfState } from "./models/wf-state.as";

export const ALL_MODELS = [
  Tenant,
  DemoUser,
  Department,
  Project,
  Task,
  Comment,
  Document,
  AuditEntry,
  DemoWfState,
  DemoAuthCredential,
  DemoFederatedIdentity,
  DemoPendingAuthorization,
  DemoAuthCode,
  DemoDynamicClient,
] as const;

export interface AppDb {
  db: DbSpace;
  tables: {
    tenants: AtscriptDbTable<typeof Tenant>;
    users: AtscriptDbTable<typeof DemoUser>;
    departments: AtscriptDbTable<typeof Department>;
    projects: AtscriptDbTable<typeof Project>;
    tasks: AtscriptDbTable<typeof Task>;
    comments: AtscriptDbTable<typeof Comment>;
    documents: AtscriptDbTable<typeof Document>;
    audit: AtscriptDbTable<typeof AuditEntry>;
    wfStates: AtscriptDbTable<typeof DemoWfState>;
    credentials: AtscriptDbTable<typeof DemoAuthCredential>;
    federatedIdentities: AtscriptDbTable<typeof DemoFederatedIdentity>;
    pendingAuthorizations: AtscriptDbTable<typeof DemoPendingAuthorization>;
    authCodes: AtscriptDbTable<typeof DemoAuthCode>;
    dynamicClients: AtscriptDbTable<typeof DemoDynamicClient>;
  };
  close: () => void;
}

export function createAppDb(dbPath: string): AppDb {
  // Better-sqlite3 needs the parent directory to exist for file paths. The
  // `:memory:` sentinel is opened directly and never touches disk, so we skip
  // the mkdir to avoid creating a stray `.` directory in cwd.
  if (dbPath !== ":memory:") {
    mkdirSync(path.dirname(dbPath), { recursive: true });
  }

  // For `:memory:`, better-sqlite3 keeps the DB alive only as long as the
  // single underlying connection. The adapter factory is invoked once per
  // table on first access — capturing the same `driver` instance ensures every
  // table sees the same in-memory database.
  const driver = new BetterSqlite3Driver(dbPath);
  const db = new DbSpace(() => new SqliteAdapter(driver));

  const tables: AppDb["tables"] = {
    tenants: db.getTable(Tenant),
    users: db.getTable(DemoUser),
    departments: db.getTable(Department),
    projects: db.getTable(Project),
    tasks: db.getTable(Task),
    comments: db.getTable(Comment),
    documents: db.getTable(Document),
    audit: db.getTable(AuditEntry),
    wfStates: db.getTable(DemoWfState),
    credentials: db.getTable(DemoAuthCredential),
    federatedIdentities: db.getTable(DemoFederatedIdentity),
    pendingAuthorizations: db.getTable(DemoPendingAuthorization),
    authCodes: db.getTable(DemoAuthCode),
    dynamicClients: db.getTable(DemoDynamicClient),
  };

  return {
    db,
    tables,
    close: () => driver.close(),
  };
}

/**
 * Sync schema for ALL tables. Idempotent — safe to call repeatedly. Acquires
 * the `__atscript_control` distributed lock under the hood, so multi-process
 * boot is also safe.
 */
export async function syncAppSchema(appDb: AppDb): Promise<void> {
  await syncSchema(appDb.db, [...ALL_MODELS]);
}
