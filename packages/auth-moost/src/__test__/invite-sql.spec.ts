import type { UserCredentials } from "@aooth/user";
import { type AuthUserTable, UsersStoreAtscriptDb } from "@aooth/user/atscript-db";
import { AoothUserCredentials } from "@aooth/user/atscript-db/model";
import { AtscriptDbTable } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import {
  completeAccept,
  FlowWorkflow,
  INVITEE_PASSWORD,
  issueInvite,
  prepareFlowApp,
  type PreparedFlowApp,
} from "./flow-utils";

// A pending invite written before 0.2 has no `account.inviteNonce`; on a SQL
// store the column reads back as NULL. The invite accept gates must treat it
// like an absent marker — while a real re-invite still supersedes the link.

let driver: BetterSqlite3Driver;
let table: AtscriptDbTable;
/** Issue the next invite the way aooth did before 0.2 (no link marker). */
let issueLegacy = false;

@Inherit()
@Injectable()
@Controller()
class PreMarkerWorkflow extends FlowWorkflow {
  override async createUser(ctx: AuthWfCtx): Promise<undefined> {
    await super.createUser(ctx);
    if (issueLegacy) {
      delete ctx.admin!.inviteNonce;
      await table.updateOne({ id: ctx.subject, account: { inviteNonce: null } });
    }
    return undefined;
  }
}

/** Issue an invite to `email`; the issue phase must succeed. */
async function invite(app: PreparedFlowApp, email: string) {
  const res = await issueInvite(app, email);
  expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
}

/** The stored row as SQLite holds it (bypassing the store's read mapping). */
async function rawAccount(email: string): Promise<Record<string, unknown>> {
  const row = (await table.findOne({ filter: { username: email } })) as UserCredentials | null;
  return row!.account as unknown as Record<string, unknown>;
}

describe("A1: pre-0.2 invites on a SQL user store", () => {
  let app: PreparedFlowApp;

  beforeEach(async () => {
    driver = new BetterSqlite3Driver(":memory:");
    table = new AtscriptDbTable(AoothUserCredentials, new SqliteAdapter(driver));
    await table.ensureTable();
    await table.syncIndexes();
    issueLegacy = false;
    app = await prepareFlowApp({
      workflowClass: PreMarkerWorkflow,
      workflowOpts: { autoLoginOnInvite: false },
      userStore: new UsersStoreAtscriptDb({ table: table as unknown as AuthUserTable }),
    });
  });

  afterEach(() => {
    driver.close();
  });

  it("a pending invite with a NULL inviteNonce resumes and accepts", async () => {
    issueLegacy = true;
    await invite(app, "legacy@x.test");
    expect((await rawAccount("legacy@x.test")).inviteNonce).toBeNull();

    const opened = await app.submit(app.emails[0].token);
    expect(opened.status, JSON.stringify(opened.body)).toBeLessThan(300);
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const res = await completeAccept(app, opened.body.wfs);
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);

    const user = (await app.users.findByHandle("legacy@x.test"))!;
    expect(user.account.pendingInvitation).toBe(false);
    expect(user.account.active).toBe(true);
    expect(await app.users.verifyPassword(user.id, INVITEE_PASSWORD)).toBe(true);
  });

  it("a re-invite still supersedes the pre-0.2 link with 410", async () => {
    issueLegacy = true;
    await invite(app, "legacy@x.test");
    issueLegacy = false;
    await invite(app, "legacy@x.test"); // 'reuse' — writes a real marker
    expect(app.emails).toHaveLength(2);

    const stale = await app.submit(app.emails[0].token);
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });
    const fresh = await app.submit(app.emails[1].token);
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  });
});
