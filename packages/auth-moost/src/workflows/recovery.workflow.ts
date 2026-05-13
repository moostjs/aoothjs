/**
 * RecoveryWorkflow — `wfid = 'auth.recovery'`.
 *
 * Steps (mirrors the canonical demo pattern of separating "send" from "collect"):
 *   1. `requestRecovery` — collect email; resolves the user but never reveals
 *                           whether it existed. On unknown email the workflow
 *                           short-circuits via `useWfFinished().set(sent:true)`
 *                           and the following steps are skipped via a guard.
 *   2. `sendLink`        — emits `outletEmail()` ONCE (first run). On resume
 *                           after the magic-link click the flag `linkSent` is
 *                           already true so the step advances without re-emitting.
 *   3. `setPassword`     — collects + sets the new password, issues tokens.
 *
 * Magic-link URL: `buildMagicLinkUrl('recovery', token)` → e.g.
 * `https://app.example.com/wf/trigger?wfs=<token>`.
 */
import { AuthCredential } from "@aoothjs/auth";
import { UserAuthError, UserService } from "@aoothjs/user";
import {
  outletEmail,
  Step,
  StepTTL,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Injectable, useControllerContext } from "moost";

import { EmailIdentifierForm, SetPasswordForm } from "../atscript/models/forms.as.js";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import { Public } from "../auth.decorator";
import { MoostAuthWorkflowConfig } from "../workflow-config";
import {
  buildFinishedCookies,
  httpInputRequired,
  translatePasswordSetError,
  validateFormInput,
} from "./wf-helpers";

/** Server-only workflow context. `username` is set when the email matches. */
export interface RecoveryWfCtx {
  username?: string;
  email?: string;
  /** Marks that `sendLink` already emitted the outlet (resume → advance). */
  linkSent?: boolean;
}

@Injectable("FOR_EVENT")
@Controller()
@Public()
export class RecoveryWorkflow {
  @Workflow("auth.recovery")
  @WorkflowSchema<RecoveryWfCtx>([
    { id: "recoveryRequest" },
    // Both later steps require `username` — skip everything for unknown emails.
    { id: "recoverySendLink", condition: (ctx) => !!ctx.username },
    { id: "recoverySetPassword", condition: (ctx) => !!ctx.username },
  ])
  flow(): void {}

  @Step("recoveryRequest")
  async requestRecovery(
    @WorkflowParam("input") input: { email?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(EmailIdentifierForm, ctx);
    const errors = validateFormInput(EmailIdentifierForm, input);
    if (errors) return httpInputRequired(EmailIdentifierForm, ctx, errors);

    const cc = useControllerContext();
    const users = await cc.instantiate(UserService);

    // Resolve user; lookup uses `email` as username — recovery on apps that
    // separate email from username should ship a custom workflow.
    let username: string | undefined;
    try {
      const user = await users.getUser(input.email as string);
      username = user.username;
    } catch (err) {
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
    }

    ctx.email = input.email as string;
    if (username) {
      ctx.username = username;
      return undefined;
    }

    // Unknown email — short-circuit with the generic response and the
    // schema's guard on `sendLink` / `setPassword` halts here.
    useWfFinished().set({
      type: "data",
      value: { sent: true, message: "If an account exists, you will receive instructions." },
    });
    return undefined;
  }

  @Step("recoverySendLink")
  @StepTTL(60 * 60 * 1000) // override at outlet level if needed
  async sendLink(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    // First run: emit outletEmail; engine persists state and our email outlet
    // ships the magic link. Resume run (link clicked): `linkSent` is set
    // so we advance to `setPassword` without re-sending.
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;

    const cc = useControllerContext();
    const wfConfig = await cc.instantiate(MoostAuthWorkflowConfig);
    const config = wfConfig.config;
    return outletEmail(ctx.email as string, "recovery.magicLink", {
      username: ctx.username,
      expiresAtMs: config.recoveryTokenTtlMs,
    });
  }

  @Step("recoverySetPassword")
  async setPassword(
    @WorkflowParam("input") input: { newPassword?: string; confirmPassword?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(SetPasswordForm, ctx);
    const errors = validateFormInput(SetPasswordForm, input);
    if (errors) return httpInputRequired(SetPasswordForm, ctx, errors);

    if (input.newPassword !== input.confirmPassword) {
      return httpInputRequired(SetPasswordForm, ctx, {
        confirmPassword: "Passwords do not match",
      });
    }

    if (!ctx.username) {
      return httpInputRequired(SetPasswordForm, ctx, { __form: "Recovery session expired" });
    }

    const cc = useControllerContext();
    const [users, auth, config] = await Promise.all([
      cc.instantiate(UserService),
      cc.instantiate(AuthCredential),
      cc.instantiate(MoostAuthConfig),
    ]);

    try {
      await users.setPassword(ctx.username, input.newPassword as string);
    } catch (err) {
      translatePasswordSetError(err);
    }
    const issue = await auth.issue(ctx.username);
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(config, ctx.username, issue),
      cookies: buildFinishedCookies(config, issue),
    });
    return undefined;
  }
}
