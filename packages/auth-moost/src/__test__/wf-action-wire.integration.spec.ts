/**
 * Integration tests for the action wire — the shape `<AsWfForm>` emits when a
 * `@ui.form.action` field button is clicked.
 *
 * The canonical wire envelope `<AsWfForm>` emits is
 * `{ wfs, input: { action, formData? } }`: action + (optional) form data
 * travel together inside the workflow `input` envelope. The wf engine reads
 * `body.input.action` natively via `useAtscriptWf(Form).resolveAction()` —
 * no app-level bridging.
 *
 * These tests drive the real `AuthController.triggerWf()` → `@WfTrigger` →
 * `WfTriggerProvider.handle()` → `handleAsOutletRequest` path through a full
 * Moost + MoostHttp + MoostWf stack and assert the canonical envelope for the
 * `forgotPassword` alt-action declared on the bundled `LoginCredentialsForm`.
 */
import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";
import { MoostHttp } from "@moostjs/event-http";
import { MoostWf } from "@moostjs/event-wf";
import { createHttpApp } from "@wooksjs/event-http";
import { describe, expect, it } from "vite-plus/test";
import { Controller, createProvideRegistry, getMoostInfact, Inherit, Moost } from "moost";
import { Wooks } from "wooks";

import { AuthController } from "../auth.controller";
import { authGuardInterceptor } from "../auth.guard";
import { AuthOpts } from "../auth.opts";
import { ConsentStore } from "../consent.store";
import { LoginWorkflow } from "../workflows/index";

interface AuthAppHandle {
  request: (
    path: string,
    init?: RequestInit & { json?: unknown },
  ) => Promise<{ status: number; body: Record<string, unknown> | null }>;
}

async function buildAuthApp(): Promise<AuthAppHandle> {
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const wooksHttp = createHttpApp(undefined, new Wooks());
  const http = moost.adapter(new MoostHttp(wooksHttp));
  moost.adapter(new MoostWf());

  const auth = new AuthCredential({
    store: new CredentialStoreMemory(),
    method: "token",
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "always" },
  });
  const users = new UserService(new UserStoreMemory());
  const authOpts = new AuthOpts();
  const consentStore = new ConsentStore();

  @Inherit()
  @Controller("auth/login")
  class DemoLoginWorkflow extends LoginWorkflow {
    constructor(u: UserService, a: AuthCredential, ao: AuthOpts, cs: ConsentStore) {
      super({}, u, a, ao, cs);
    }
    // Post-resolver reshape: alt-cred policy now flows through
    // `resolveAlternateCredentials(ctx)` rather than the ctor opts.
    protected override resolveAlternateCredentials() {
      return {
        forgotPassword: true,
        signup: false,
        magicLink: false,
        magicLinkSkipsMfa: false,
        ssoProviders: [],
        recoveryUrl: "/recover",
        signupUrl: "/signup",
        embedRecovery: false,
      };
    }
  }

  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => auth],
      [UserService, () => users],
      [AuthOpts, () => authOpts],
      [ConsentStore, () => consentStore],
    ),
  );
  moost.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
  moost.registerControllers(AuthController, DemoLoginWorkflow);

  await moost.init();

  async function request(
    path: string,
    init: RequestInit & { json?: unknown } = {},
  ): Promise<{ status: number; body: Record<string, unknown> | null }> {
    const { json, ...rest } = init;
    const headers = new Headers(rest.headers);
    let body = rest.body;
    if (json !== undefined) {
      body = JSON.stringify(json);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
    const response = await http.request(path, { ...rest, headers, body });
    if (!response) return { status: 0, body: null };
    const text = await response.text();
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = text ? (JSON.parse(text) as Record<string, unknown>) : null;
    } catch {
      parsed = { _raw: text };
    }
    return { status: response.status, body: parsed };
  }

  return { request };
}

describe("WfTriggerProvider — action wire (`{ wfs, input: { action, formData? } }`)", () => {
  it("inline forgotPassword field action → finishWf({ next: immediate redirect to /recover?username=...}) envelope", async () => {
    const app = await buildAuthApp();

    // Phase 1: start auth.login → server pauses and returns the credentials form.
    const start = await app.request("/auth/trigger", {
      method: "POST",
      json: { wfid: "auth/login/flow" },
    });
    expect(start.status).toBeLessThan(400);
    const wfs = start.body?.wfs as string | undefined;
    expect(typeof wfs).toBe("string");

    // Phase 2: client sends the canonical action wire — action lives inside
    // `input`. (This is what `<AsWfForm>` emits when a user clicks a
    // `@ui.form.action` inline link/button on a field.)
    const click = await app.request("/auth/trigger", {
      method: "POST",
      json: { wfs, input: { action: "forgotPassword" } },
    });

    // Must be a successful HTTP response (not 4xx/5xx, not a 410 expired).
    expect(click.status).toBeLessThan(400);

    // The envelope shape pinned here is the new `WfFinished` contract:
    //   { finished: true, next: { trigger: "immediate", action: {...} } }
    expect(click.body).toMatchObject({
      finished: true,
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: expect.stringMatching(/^\/recover(\?username=.*)?$/),
          reason: "forgot-password",
        },
      },
    });
  });

  it("action wire with typed username carries the prefill to /recover?username=...", async () => {
    // Mirrors the realistic UI scenario: user types a username, then clicks
    // the inline "Forgot password?" link. The wire carries the action AND a
    // partial input snapshot (`formData`) so the recovery form pre-fills.
    const app = await buildAuthApp();

    const start = await app.request("/auth/trigger", {
      method: "POST",
      json: { wfid: "auth/login/flow" },
    });
    const wfs = start.body?.wfs as string;

    const click = await app.request("/auth/trigger", {
      method: "POST",
      // action-with-data wire shape: action + partial formData under the
      // single workflow `input` envelope. The credentials step's typed-username
      // is sourced from `input.formData.username` via `getInputField`.
      json: { wfs, input: { action: "forgotPassword", formData: { username: "alice" } } },
    });

    expect(click.status).toBeLessThan(400);
    const next = (click.body?.next ?? null) as {
      trigger: string;
      action: { type: string; target: string; reason?: string };
    } | null;
    expect(next?.trigger).toBe("immediate");
    expect(next?.action.type).toBe("redirect");
    expect(next?.action.target).toBe("/recover?username=alice");
    expect(next?.action.reason).toBe("forgot-password");
  });
});
