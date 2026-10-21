import type { TArbacRole } from "@aooth/arbac-moost";
import { describe, expect, it } from "vite-plus/test";

import { prepareFlowApp } from "./flow-utils";

// A rule scope returning null/undefined grants nothing — on ARBAC-guarded
// workflow steps too (the authorize interceptor runs for every event kind).

async function issueAs(scope: () => object | null) {
  const userRoles = new Map<string, string[]>();
  const app = await prepareFlowApp({
    arbac: {
      roles: [
        {
          id: "inviter",
          rules: [{ resource: "auth.invite", action: "*", scope }],
        } satisfies TArbacRole<object, object>,
      ],
      userRoles,
    },
  });
  const admin = await app.seedUser("admin", "Password123!");
  userRoles.set(admin, ["inviter"]);
  const { accessToken } = await app.auth.issue(admin);
  const start = await app.start("auth/invite/start", { authorization: `Bearer ${accessToken}` });
  return { app, start };
}

describe("nullish scope on an ARBAC-guarded workflow step", () => {
  it("denies the invite issue phase with 403", async () => {
    const { app, start } = await issueAs(() => null);
    expect(start.status).toBe(403);
    expect(app.emails).toEqual([]);
  });

  it("a non-null scope still lets the issue phase start", async () => {
    const { start } = await issueAs(() => ({}));
    expect(start.status, JSON.stringify(start.body)).toBe(201);
    expect(start.body.inputRequired?.payload?.id).toBe("InviteForm");
  });
});
