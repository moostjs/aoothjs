/**
 * LoginWorkflow — `wfid = 'auth.login'`.
 *
 * Steps:
 *   1. `init`         — copies `this.opts` → `ctx.opts` (per WF.md convention).
 *   2. `credentials`  — collect username/password, run `UserService.login`.
 *                       If `mfaRequired`, branch into step 3; otherwise step 4.
 *   3. `mfa`          — collect TOTP code (skipped when `!mfaRequired`).
 *   4. `issue`        — issue an `AuthCredential`, write cookies, finish.
 */
import { AuthCredential } from "@aoothjs/auth";
import { UserAuthError, UserService } from "@aoothjs/user";
import { HttpError } from "@moostjs/event-http";
import { Step, useWfFinished, Workflow, WorkflowParam, WorkflowSchema } from "@moostjs/event-wf";
import { Controller, Injectable } from "moost";

import { LoginCredentialsForm, MfaCodeForm } from "../atscript/models/forms.as.js";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import { Public } from "../auth.decorator";
import { LoginWorkflowOptions } from "./login.workflow.options";
import { buildFinishedCookies, httpInputRequired, validateFormInput } from "./wf-helpers";

export interface LoginWfCtx {
  opts?: LoginWorkflowOptions;
  username?: string;
  mfaRequired?: boolean;
}

@Injectable("FOR_EVENT")
@Controller()
@Public()
export class LoginWorkflow {
  constructor(
    private readonly opts: LoginWorkflowOptions,
    private readonly users: UserService,
    private readonly auth: AuthCredential,
    private readonly authConfig: MoostAuthConfig,
  ) {}

  @Workflow("auth.login")
  @WorkflowSchema<LoginWfCtx>([
    { id: "init" },
    { id: "credentials" },
    { id: "mfa", condition: (ctx) => !!ctx.mfaRequired },
    { id: "issue" },
  ])
  flow(): void {}

  @Step("init")
  init(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
    ctx.opts = this.opts;
    return undefined;
  }

  @Step("credentials")
  async credentials(
    @WorkflowParam("input") input: { username?: string; password?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(LoginCredentialsForm, ctx);
    const errors = validateFormInput(LoginCredentialsForm, input);
    if (errors) return httpInputRequired(LoginCredentialsForm, ctx, errors);

    try {
      const result = await this.users.login(input.username as string, input.password as string);
      ctx.username = result.user.username;
      ctx.mfaRequired = result.mfaRequired;
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          // Surface as 423 — matches the REST controller's translation.
          throw new HttpError(423, "Account locked");
        }
        // INVALID_CREDENTIALS / NOT_FOUND / INACTIVE → opaque __form error.
        return httpInputRequired(LoginCredentialsForm, ctx, { __form: "Invalid credentials" });
      }
      throw err;
    }
    return undefined;
  }

  @Step("mfa")
  async mfa(
    @WorkflowParam("input") input: { code?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(MfaCodeForm, ctx);
    const errors = validateFormInput(MfaCodeForm, input);
    if (errors) return httpInputRequired(MfaCodeForm, ctx, errors);

    if (!ctx.username) {
      // Should be unreachable — `credentials` always sets it before we get here.
      throw new HttpError(500, "Workflow state corrupted: missing username");
    }

    try {
      await this.users.verifyMfa(ctx.username, input.code as string);
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          throw new HttpError(423, "Account locked");
        }
        if (err.type === "INACTIVE") {
          // Account deactivated between credentials & mfa step.
          throw new HttpError(401, "Invalid credentials");
        }
        if (err.type === "MFA_NOT_CONFIGURED") {
          // Reachable only if MFA methods were deleted between login & mfa step.
          throw new HttpError(400, "No TOTP MFA configured");
        }
        if (err.type === "MFA_INVALID") {
          // Lockout was just tripped — surface 423 so the client stops retrying.
          if (err.details?.lockEnds !== undefined) {
            throw new HttpError(423, "Account locked");
          }
          return httpInputRequired(MfaCodeForm, ctx, { code: "Invalid code" });
        }
      }
      throw err;
    }
    return undefined;
  }

  @Step("issue")
  async issue(@WorkflowParam("context") ctx: LoginWfCtx): Promise<void> {
    if (!ctx.username) {
      throw new HttpError(500, "Workflow state corrupted: missing username");
    }
    const issue = await this.auth.issue(ctx.username);
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(this.authConfig, ctx.username, issue),
      cookies: buildFinishedCookies(this.authConfig, issue),
    });
  }
}
