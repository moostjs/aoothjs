/**
 * InviteWorkflow — `wfid = 'auth.invite'`.
 *
 * Steps:
 *   1. `init`         — copies `this.opts` → `ctx.opts`.
 *   2. `inviteCreate` — admin enters email + optional roles; validates uniqueness.
 *   3. `inviteSendLink` — emits `outletEmail` once.
 *   4. `inviteAccept`   — sets password, creates + activates user, issues tokens.
 *
 * Admin protection is the consumer's responsibility (mount the invite trigger
 * behind admin RBAC). See `createAuthEmailOutlet` for the recommended split.
 */
import { AuthCredential } from "@aoothjs/auth";
import { UserAuthError, UserService } from "@aoothjs/user";
import { HttpError } from "@moostjs/event-http";
import {
  outletEmail,
  Step,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Injectable } from "moost";

import { InviteForm, SetPasswordForm } from "../atscript/models/forms.as.js";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import { Public } from "../auth.decorator";
import { InviteWorkflowOptions } from "./invite.workflow.options";
import {
  buildFinishedCookies,
  httpInputRequired,
  translatePasswordSetError,
  validateFormInput,
} from "./wf-helpers";

export interface InviteWfCtx {
  opts?: InviteWorkflowOptions;
  email?: string;
  roles?: string[];
  /** Marks that `sendLink` already emitted the outlet (resume → advance). */
  linkSent?: boolean;
}

/** Trim/split `roles` form input — `"admin, editor"` → `["admin", "editor"]`. */
export function parseInviteRoles(input?: string): string[] {
  if (!input) return [];
  return input
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
}

@Injectable("FOR_EVENT")
@Controller()
@Public()
export class InviteWorkflow {
  constructor(
    private readonly opts: InviteWorkflowOptions,
    private readonly users: UserService,
    private readonly auth: AuthCredential,
    private readonly authConfig: MoostAuthConfig,
  ) {}

  @Workflow("auth.invite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "init" },
    { id: "inviteCreate" },
    { id: "inviteSendLink" },
    { id: "inviteAccept" },
  ])
  flow(): void {}

  @Step("init")
  init(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    ctx.opts = this.opts;
    return undefined;
  }

  @Step("inviteCreate")
  async createInvite(
    @WorkflowParam("input") input: { email?: string; roles?: string } | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(InviteForm, ctx);
    const errors = validateFormInput(InviteForm, input);
    if (errors) return httpInputRequired(InviteForm, ctx, errors);

    // Reject if the user already exists — unlike recovery, enumeration
    // resistance does not apply (only admins reach this endpoint).
    try {
      await this.users.getUser(input.email as string);
      throw new HttpError(409, "User already exists");
    } catch (err) {
      if (err instanceof HttpError) throw err;
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
    }

    ctx.email = input.email as string;
    const roles = parseInviteRoles(input.roles);
    if (roles.length > 0) ctx.roles = roles;
    return undefined;
  }

  @Step("inviteSendLink")
  sendLink(@WorkflowParam("context") ctx: InviteWfCtx): unknown {
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;

    // Runtime TTL — `@StepTTL` resolves at class-definition time, so we attach
    // `expires` to the outlet result (MoostWf only overrides when `@StepTTL`).
    return {
      ...outletEmail(ctx.email as string, "invite.magicLink", {
        ...(ctx.roles && { roles: ctx.roles }),
        expiresAtMs: this.opts.inviteTokenTtlMs,
      }),
      expires: Date.now() + this.opts.inviteTokenTtlMs,
    };
  }

  @Step("inviteAccept")
  async accept(
    @WorkflowParam("input") input: { newPassword?: string; confirmPassword?: string } | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(SetPasswordForm, ctx);
    const errors = validateFormInput(SetPasswordForm, input);
    if (errors) return httpInputRequired(SetPasswordForm, ctx, errors);

    if (input.newPassword !== input.confirmPassword) {
      return httpInputRequired(SetPasswordForm, ctx, {
        confirmPassword: "Passwords do not match",
      });
    }

    if (!ctx.email) {
      return httpInputRequired(SetPasswordForm, ctx, { __form: "Invite session expired" });
    }

    const extras = this.opts.prepareUser
      ? await this.opts.prepareUser({ email: ctx.email, roles: ctx.roles ?? [] })
      : undefined;

    try {
      await this.users.createUser(ctx.email, input.newPassword as string, extras);
    } catch (err) {
      translatePasswordSetError(err);
    }
    await this.users.activateAccount(ctx.email);
    const issue = await this.auth.issue(ctx.email);
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(this.authConfig, ctx.email, issue),
      cookies: buildFinishedCookies(this.authConfig, issue),
    });
    return undefined;
  }
}
