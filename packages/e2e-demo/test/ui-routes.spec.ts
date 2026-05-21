/**
 * Regression coverage for the class of bug where a workflow's default redirect
 * URL (e.g. RecoveryWorkflow's `postReset.loginUrl = "/login"`) is emitted by
 * the server but the SPA router has no matching route — so the user clicks
 * "Back to sign in" and lands on a 404. The original symptom was reported by
 * a human: "back to sign in button from recovery has wrong wiring, leads to
 * /login page that does not exist."
 *
 * These tests pin the bridge in BOTH directions:
 *   1. Every default URL the workflow library emits MUST resolve in the SPA
 *      router (either directly or via a redirect entry).
 *   2. Every wfid `WORKFLOW_URL_REDIRECTS` claims to bridge to MUST exist in
 *      `WORKFLOWS` — otherwise the redirect lands on `/wf?id=<missing>` and
 *      `WfPage.vue` shows "Unknown workflow id".
 *
 * If the workflow library bumps and adds a new default (or changes one), test
 * #1 fails and the bridge has to be updated. That's the loud failure the
 * earlier integration tests missed because nothing exercised the full
 * server→client redirect handoff.
 */
import { mergeInviteOpts, mergeLoginOpts, mergeRecoveryOpts } from "@aooth/auth-moost";
import { describe, expect, it } from "vite-plus/test";

import { WORKFLOW_URL_REDIRECTS } from "../src/ui/router";
import { WORKFLOWS } from "../src/ui/workflows";

/**
 * Pulls every string default that looks like a navigable URL out of the
 * resolved option pojos. Keep `/wf*` paths in (they ARE valid targets the
 * SPA serves natively); the assertion below permits both bare bridge keys
 * and `/wf...` natives. New URL options added upstream will surface here
 * automatically — the test scans values, not field names.
 */
function collectDefaultUrls(resolved: unknown): string[] {
  const out: string[] = [];
  function walk(node: unknown): void {
    if (typeof node === "string" && node.startsWith("/")) {
      out.push(node);
      return;
    }
    if (node && typeof node === "object") {
      for (const v of Object.values(node)) walk(v);
    }
  }
  walk(resolved);
  return out;
}

describe("SPA router bridges every workflow-default redirect URL", () => {
  const knownWfIds = new Set(WORKFLOWS.map((w) => w.id));
  const bridgedPaths = new Set(Object.keys(WORKFLOW_URL_REDIRECTS));

  it("login workflow defaults — every `/...` URL has a SPA bridge", () => {
    const urls = new Set(collectDefaultUrls(mergeLoginOpts({})));
    const unbridged = [...urls].filter((u) => !bridgedPaths.has(u) && !u.startsWith("/wf"));
    expect(
      unbridged,
      `LoginWorkflow defaults missing in WORKFLOW_URL_REDIRECTS: ${unbridged.join(", ")}`,
    ).toEqual([]);
  });

  it("recovery workflow defaults — every `/...` URL has a SPA bridge", () => {
    const urls = new Set(collectDefaultUrls(mergeRecoveryOpts({})));
    const unbridged = [...urls].filter((u) => !bridgedPaths.has(u) && !u.startsWith("/wf"));
    expect(
      unbridged,
      `RecoveryWorkflow defaults missing in WORKFLOW_URL_REDIRECTS: ${unbridged.join(", ")}`,
    ).toEqual([]);
  });

  it("invite workflow defaults — every `/...` URL has a SPA bridge", () => {
    const urls = new Set(collectDefaultUrls(mergeInviteOpts({})));
    const unbridged = [...urls].filter((u) => !bridgedPaths.has(u) && !u.startsWith("/wf"));
    expect(
      unbridged,
      `InviteWorkflow defaults missing in WORKFLOW_URL_REDIRECTS: ${unbridged.join(", ")}`,
    ).toEqual([]);
  });

  it("every bridged wfid is a known workflow", () => {
    for (const [path, wfid] of Object.entries(WORKFLOW_URL_REDIRECTS)) {
      expect(
        knownWfIds.has(wfid),
        `${path} bridges to unknown wfid "${wfid}" (not in WORKFLOWS)`,
      ).toBe(true);
    }
  });
});
