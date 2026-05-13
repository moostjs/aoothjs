import { formInputInterceptor } from "@atscript/moost-wf";
import { describe, expect, it } from "vite-plus/test";

import type { EmailSender } from "../email";
import type { BuildMagicLinkUrl } from "../magic-link";
import {
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  MoostAuthWorkflowConfig,
} from "../workflow-config";
import { setupAuthWorkflows } from "../workflow-setup";
import { Controller, Moost, TestAdapter, TestHandler } from "./test-utils";

const sender: EmailSender = { send: async () => undefined };
const buildUrl: BuildMagicLinkUrl = (_, t) => `https://x.test/${t}`;
const fakeStore = { id: "fake-store" };

@Controller("smoke")
class SmokeController {
  @TestHandler()
  ping(): string {
    return "pong";
  }
}

describe("setupAuthWorkflows", () => {
  it("registers MoostAuthWorkflowConfig as a DI singleton", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);

    setupAuthWorkflows(moost, {
      emailSender: sender,
      buildMagicLinkUrl: buildUrl,
      wfStateStore: fakeStore,
    });

    await moost.init();

    const infact = (await import("moost")).getMoostInfact();
    const instance = await adapter.handlers[0].getInstance();
    const cfg = await infact.getForInstance(instance, MoostAuthWorkflowConfig);
    expect(cfg).toBeInstanceOf(MoostAuthWorkflowConfig);
    expect(cfg?.config.recoveryTokenTtlMs).toBe(DEFAULT_RECOVERY_TOKEN_TTL_MS);
    expect(cfg?.config.inviteTokenTtlMs).toBe(DEFAULT_INVITE_TOKEN_TTL_MS);
    expect(cfg?.config.mfaCodeTtlMs).toBe(DEFAULT_MFA_CODE_TTL_MS);
    expect(cfg?.config.wfStateStore).toBe(fakeStore);
  });

  it("applies the form-input interceptor globally", async () => {
    const moost = new Moost();
    const adapter = new TestAdapter();
    moost.adapter(adapter);
    moost.registerControllers(SmokeController);

    setupAuthWorkflows(moost, {
      emailSender: sender,
      buildMagicLinkUrl: buildUrl,
      wfStateStore: fakeStore,
    });
    await moost.init();

    const interceptors = (moost as unknown as { interceptors: Array<{ handler: unknown }> })
      .interceptors;
    const handlers = interceptors.map((i) => i.handler);
    // The interceptor handler is the value returned by formInputInterceptor() — an
    // object with `priority`/`error` keys. We compare structurally rather than by
    // identity because each call to the factory returns a fresh object.
    const expected = formInputInterceptor();
    const matched = handlers.some(
      (h) =>
        typeof h === "object" &&
        h !== null &&
        "priority" in h &&
        (h as { priority: unknown }).priority === expected.priority &&
        typeof (h as { error?: unknown }).error === "function",
    );
    expect(matched).toBe(true);
  });

  it("throws on missing required options", () => {
    const moost = new Moost();
    moost.adapter(new TestAdapter());

    expect(() =>
      setupAuthWorkflows(moost, {
        // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid
        emailSender: undefined as any,
        buildMagicLinkUrl: buildUrl,
        wfStateStore: fakeStore,
      }),
    ).toThrow(/emailSender/);

    expect(() =>
      setupAuthWorkflows(moost, {
        emailSender: sender,
        // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid
        buildMagicLinkUrl: undefined as any,
        wfStateStore: fakeStore,
      }),
    ).toThrow(/buildMagicLinkUrl/);

    expect(() =>
      setupAuthWorkflows(moost, {
        emailSender: sender,
        buildMagicLinkUrl: buildUrl,
        wfStateStore: null,
      }),
    ).toThrow(/wfStateStore/);
  });
});
