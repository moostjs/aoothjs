import { describe, expect, it } from "vite-plus/test";

import type { AuthEmailEvent } from "@aooth/auth";
import { Controller, Inherit, Injectable } from "moost";

import { createAuthEmailOutlet } from "../workflows/auth-email-outlet";
import {
  FlowWorkflow,
  inLocale,
  localizedHttpApp,
  prepareFlowApp,
  type PreparedFlowApp,
} from "./flow-utils";

// Deliveries carry the request's locale so a sender can localize them.

const inviteLinkUrl = (token: string) => `https://app.test/invite?wfs=${token}`;

async function issueInvite(app: PreparedFlowApp, email: string, headers?: Record<string, string>) {
  const start = await app.start("auth/invite/start", headers);
  return app.submit(start.body.wfs, { formData: { email, roles: [] } }, headers);
}

describe("delivery locale", () => {
  it("deliver() payloads carry the request's locale", async () => {
    const delivered: Array<{ kind: string; locale?: string }> = [];
    @Inherit()
    @Injectable()
    @Controller()
    class Delivering extends FlowWorkflow {
      protected override deliver(payload: { kind: string; locale?: string }): void {
        delivered.push(payload);
      }
    }
    const app = await prepareFlowApp({
      workflowClass: Delivering,
      workflowOpts: { inviteDelivery: "deliver", inviteLinkUrl },
      httpApp: localizedHttpApp,
    });
    await issueInvite(app, "de@x.test", { "accept-language": "de-CH, de;q=0.9" });
    await issueInvite(app, "en@x.test");
    expect(delivered.map((p) => [p.kind, p.locale])).toEqual([
      ["invite-link", "de"],
      ["invite-link", "en"],
    ]);
  });

  it("no locale (no resolver) → the payload has no locale", async () => {
    const delivered: object[] = [];
    @Inherit()
    @Injectable()
    @Controller()
    class Delivering extends FlowWorkflow {
      protected override deliver(payload: object): void {
        delivered.push(payload);
      }
    }
    const app = await prepareFlowApp({
      workflowClass: Delivering,
      workflowOpts: { inviteDelivery: "deliver", inviteLinkUrl },
    });
    await issueInvite(app, "x@x.test");
    expect(delivered).toHaveLength(1);
    expect(delivered[0]).not.toHaveProperty("locale");
  });

  it("createAuthEmailOutlet stamps AuthEmailEvent.locale (undefined outside a request)", async () => {
    const sent: AuthEmailEvent[] = [];
    const outlet = createAuthEmailOutlet({
      emailSender: { send: async (event) => void sent.push(event) },
      buildMagicLinkUrl: (_kind, token) => `https://app.test/m?wfs=${token}`,
      magicLinkTtlMs: () => 60_000,
    });
    const request = { target: "a@x.test", template: "recovery.magicLink", context: {} };
    await inLocale("de", () => outlet.deliver(request as never, "tok"));
    await outlet.deliver(request as never, "tok2");
    expect(sent.map((e) => e.locale)).toEqual(["de", undefined]);
    expect(sent[1]).not.toHaveProperty("locale");
  });
});
