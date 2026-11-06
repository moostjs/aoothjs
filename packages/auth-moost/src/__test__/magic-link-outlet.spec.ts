import type { WfOutlet, WfOutletRequest } from "@moostjs/event-wf";
import { createEventContext } from "@wooksjs/event-core";
import { describe, expect, it } from "vite-plus/test";

import { createMagicLinkOutlet, MAGIC_LINK_OUTLET } from "../workflow/magic-link-outlet";
import { quietLogger } from "./flow-utils";

// WHY: the outlet is where "known" and "unknown" identifiers would diverge —
// it must answer identically whether it sent, skipped, or failed to send.

function emailOutlet(calls: Array<{ request: WfOutletRequest; token: string }>, fail = false) {
  return {
    name: "email",
    tokenDelivery: "out-of-band",
    async deliver(request, token) {
      calls.push({ request, token });
      if (fail) throw new Error("smtp down");
      return { response: { sent: true, outlet: "email", extra: "leak" } };
    },
  } satisfies WfOutlet;
}

const request = (deliver: boolean): WfOutletRequest => ({
  outlet: MAGIC_LINK_OUTLET,
  target: deliver ? "a@example.test" : "",
  template: "recovery.magicLink",
  context: { deliver, expiresAtMs: 900_000 },
});

const run = <T>(fn: () => Promise<T>) => createEventContext({ logger: quietLogger }, fn);

describe("createMagicLinkOutlet", () => {
  it("forwards a link to the email outlet without its private `deliver` flag", async () => {
    const calls: Array<{ request: WfOutletRequest; token: string }> = [];
    const out = createMagicLinkOutlet(() => emailOutlet(calls));
    const res = await run(() => out.deliver(request(true), "magic-link.tok"));
    expect(res).toEqual({ response: { sent: true, outlet: "email" } });
    expect(calls).toHaveLength(1);
    expect(calls[0].token).toBe("magic-link.tok");
    expect(calls[0].request).toMatchObject({ outlet: "email", target: "a@example.test" });
    expect(calls[0].request.context).toEqual({ expiresAtMs: 900_000 });
  });

  it("sends nothing when the step decided not to, with the same answer", async () => {
    const calls: Array<{ request: WfOutletRequest; token: string }> = [];
    const out = createMagicLinkOutlet(() => emailOutlet(calls));
    const res = await run(() => out.deliver(request(false), "magic-link.tok"));
    expect(res).toEqual({ response: { sent: true, outlet: "email" } });
    expect(calls).toHaveLength(0);
  });

  it("answers the same when delivery fails (logged, not reported)", async () => {
    const out = createMagicLinkOutlet(() => emailOutlet([], true));
    const res = await run(() => out.deliver(request(true), "magic-link.tok"));
    expect(res).toEqual({ response: { sent: true, outlet: "email" } });
  });

  it("fails alike for every request when no email outlet is registered", async () => {
    const out = createMagicLinkOutlet(() => undefined);
    await expect(run(() => out.deliver(request(true), "t"))).rejects.toThrow(/email` outlet/);
    await expect(run(() => out.deliver(request(false), "t"))).rejects.toThrow(/email` outlet/);
  });
});
