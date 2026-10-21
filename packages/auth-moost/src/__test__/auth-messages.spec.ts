import { describe, expect, it } from "vite-plus/test";

import {
  AOOTH_MESSAGES,
  type AoothMessageCode,
  renderAoothMessage,
  resolveAoothMessage,
} from "../workflow/auth-messages";
import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";

import { ConsentStore } from "../consent.store";
import { AuthWorkflow, buildInviteAlreadyAcceptedEnvelope } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import { prepareFlowApp } from "./flow-utils";

// A2 (F59/F35): every user-facing workflow text is code-keyed and overridable.

describe("message catalogue", () => {
  it("renders {placeholders} and falls back to the English template", () => {
    expect(renderAoothMessage(AOOTH_MESSAGES.RESEND_WAIT, { seconds: 7 })).toBe(
      "Please wait 7s before requesting a new code.",
    );
    expect(resolveAoothMessage("INVALID_CODE", {}, { INVALID_CREDENTIALS: "x" })).toBe(
      "Invalid code",
    );
    expect(
      resolveAoothMessage("RESEND_WAIT", { seconds: 3 }, { RESEND_WAIT: "Warte {seconds}s" }),
    ).toBe("Warte 3s");
    const seen: Array<[AoothMessageCode, unknown]> = [];
    const fn = (code: AoothMessageCode, params: object) => {
      seen.push([code, params]);
      return code === "INVALID_CODE" ? "Falscher Code" : undefined;
    };
    expect(resolveAoothMessage("INVALID_CODE", {}, fn)).toBe("Falscher Code");
    expect(resolveAoothMessage("GO_NOW", {}, fn)).toBe("Go now");
    expect(seen.map(([c]) => c)).toEqual(["INVALID_CODE", "GO_NOW"]);
  });

  it("the invite-already-accepted envelope uses the overrides", () => {
    const env = buildInviteAlreadyAcceptedEnvelope({
      loginUrl: "/login",
      alreadyAcceptedRedirectUrl: "/again",
      messages: { INVITE_ALREADY_ACCEPTED: "Schon angenommen", GO_TO_SIGN_IN: "Anmelden" },
    });
    expect(env.message?.text).toBe("Schon angenommen");
    const next = env.next as { primary: { label: string }; options: Array<{ label: string }> };
    expect(next.primary.label).toBe("Anmelden");
    expect(next.options[0].label).toBe("Request a new invite");
  });
});

describe("AuthWorkflow messages option", () => {
  it("a failed sign-in answers with the overridden text", async () => {
    const app = await prepareFlowApp({
      workflowOpts: { messages: { INVALID_CREDENTIALS: "Ungültige Anmeldedaten" } },
    });
    await app.seedUser("alice", "Password123!");
    const start = await app.start("auth/login/flow");
    const res = await app.submit(start.body.wfs, {
      formData: { username: "alice", password: "nope" },
    });
    expect(res.body.inputRequired.context.errors).toEqual({ __form: "Ungültige Anmeldedaten" });
  });

  it("invite HttpErrors carry a stable code next to the resolved text", async () => {
    const users = new UserService(new UserStoreMemory());
    const flow = new AuthWorkflow(
      { messages: (code) => (code === "USER_ALREADY_EXISTS" ? "Gibt es" : undefined) },
      users,
      new AuthCredential({ store: new CredentialStoreMemory() }),
      new ConsentStore(),
    );
    await users.createUser("taken@x.test", "Password123!");
    const ctx = { email: "taken@x.test", admin: { userExtras: {} } } as AuthWfCtx;
    const err = await flow.createUser(ctx).catch((e: unknown) => e);
    expect((err as { body: unknown }).body).toMatchObject({
      statusCode: 409,
      message: "Gibt es",
      code: "USER_ALREADY_EXISTS",
    });
  });
});
