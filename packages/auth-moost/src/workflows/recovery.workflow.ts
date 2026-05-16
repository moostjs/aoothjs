/**
 * RecoveryWorkflow — `wfid = 'auth.recovery'`.
 *
 * Steps:
 *   1. `init`               — copies `this.opts` → `ctx.opts`.
 *   2. `recoveryRequest`    — collect email; resolves the user but never reveals
 *                              whether it existed. Unknown email short-circuits.
 *   3. `recoverySendLink`   — emits `outletEmail()` ONCE; pauses for magic-link click.
 *   4. `recoverySetPassword` — sets new password, issues tokens.
 */
import { AuthCredential } from "@aoothjs/auth";
import { UserAuthError, UserService } from "@aoothjs/user";
import {
  outletEmail,
  Step,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Injectable } from "moost";

import { EmailIdentifierForm, SetPasswordForm } from "../atscript/models/forms.as.js";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import { Public } from "../auth.decorator";
import { RecoveryWorkflowOptions } from "./recovery.workflow.options";
import {
  buildFinishedCookies,
  httpInputRequired,
  translatePasswordSetError,
  validateFormInput,
} from "./wf-helpers";

export interface RecoveryWfCtx {
  opts?: RecoveryWorkflowOptions;
  username?: string;
  email?: string;
  /** Marks that `sendLink` already emitted the outlet (resume → advance). */
  linkSent?: boolean;
}

@Injectable("FOR_EVENT")
@Controller()
@Public()
export class RecoveryWorkflow {
  constructor(
    private readonly opts: RecoveryWorkflowOptions,
    private readonly users: UserService,
    private readonly auth: AuthCredential,
    private readonly authConfig: MoostAuthConfig,
  ) {}

  @Workflow("auth.recovery")
  @WorkflowSchema<RecoveryWfCtx>([
    { id: "init" },
    { id: "recoveryRequest" },
    // Both later steps require `username` — skip everything for unknown emails.
    { id: "recoverySendLink", condition: (ctx) => !!ctx.username },
    { id: "recoverySetPassword", condition: (ctx) => !!ctx.username },
  ])
  flow(): void {}

  @Step("init")
  init(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined {
    ctx.opts = this.opts;
    return undefined;
  }

  @Step("recoveryRequest")
  async requestRecovery(
    @WorkflowParam("input") input: { email?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(EmailIdentifierForm, ctx);
    const errors = validateFormInput(EmailIdentifierForm, input);
    if (errors) return httpInputRequired(EmailIdentifierForm, ctx, errors);

    // `emailToUserId` is required when the user model separates `username` and
    // `email`; without it we treat the email as the username (resolver === null
    // result intentionally short-circuits → enumeration-resistant response).
    let username: string | undefined;
    try {
      const userId = await (this.opts.emailToUserId?.(input.email as string) ??
        (input.email as string));
      if (userId) {
        const user = await this.users.getUser(userId);
        username = user.username;
      }
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
  sendLink(@WorkflowParam("context") ctx: RecoveryWfCtx): unknown {
    // First run: emit outletEmail; engine persists state and our email outlet
    // ships the magic link. Resume run (link clicked): `linkSent` is set
    // so we advance to `setPassword` without re-sending.
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;

    // Runtime TTL — `@StepTTL` resolves at class-definition time, so we attach
    // `expires` to the outlet result (MoostWf only overrides when `@StepTTL`).
    return {
      ...outletEmail(ctx.email as string, "recovery.magicLink", {
        username: ctx.username,
        expiresAtMs: this.opts.recoveryTokenTtlMs,
      }),
      expires: Date.now() + this.opts.recoveryTokenTtlMs,
    };
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

    try {
      await this.users.setPassword(ctx.username, input.newPassword as string);
    } catch (err) {
      translatePasswordSetError(err);
    }
    const issue = await this.auth.issue(ctx.username);
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(this.authConfig, ctx.username, issue),
      cookies: buildFinishedCookies(this.authConfig, issue),
    });
    return undefined;
  }
}
