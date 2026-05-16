/**
 * InviteWorkflow — `wfid = 'auth.invite'`.
 *
 * Steps (mirrors the demo's separation of "send" from "collect"):
 *   1. `createInvite` — admin enters email + optional roles; validates the
 *                       email is not already in use.
 *   2. `sendLink`     — emits `outletEmail` once (first run only).
 *   3. `accept`       — collects + sets the new password, creates + activates
 *                       the user, issues tokens.
 *
 * **CRITICAL — Admin protection is the consumer's responsibility.**
 *
 * The workflow itself does NOT authenticate the caller of step 1
 * (`createInvite`). Mounting an HTTP outlet trigger with `'auth.invite'` in
 * `allow:` exposes an unauthenticated **invite-email-spam** vector: any
 * caller can submit arbitrary `email` + `roles` form values and cause your
 * configured `EmailSender` to dispatch an invite email to that address.
 *
 * Mitigations the consumer MUST apply when mounting the outlet trigger:
 *
 *  1. Mount a SEPARATE outlet trigger route for `auth.invite` and guard it
 *     with admin RBAC (e.g. `@ArbacAuthorize({ resource: 'user', action: 'invite' })`).
 *  2. OR exclude `'auth.invite'` from the public trigger's `allow:` list and
 *     drive invite creation from an admin-only endpoint that calls the
 *     workflow programmatically.
 *
 * The `accept` step (step 3) is intentionally reachable without admin auth —
 * the magic-link token IS the authorisation to complete the invite.
 *
 * `ctx.roles` from step 1 is currently NOT applied to the new user — role
 * assignment is left to a consumer-supplied post-step hook (e.g. by
 * subclassing `InviteWorkflow.accept`). This prevents accidental privilege
 * escalation by misconfigured deployments; do not weaken this default
 * without considering the implications.
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
import { Controller, Injectable, useControllerContext } from "moost";

import { InviteForm, SetPasswordForm } from "../atscript/models/forms.as.js";
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

/** Server-only context. */
export interface InviteWfCtx {
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
  @Workflow("auth.invite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteCreate" },
    { id: "inviteSendLink" },
    { id: "inviteAccept" },
  ])
  flow(): void {}

  @Step("inviteCreate")
  async createInvite(
    @WorkflowParam("input") input: { email?: string; roles?: string } | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(InviteForm, ctx);
    const errors = validateFormInput(InviteForm, input);
    if (errors) return httpInputRequired(InviteForm, ctx, errors);

    const cc = useControllerContext();
    const users = await cc.instantiate(UserService);

    // Reject if the user already exists — unlike recovery, enumeration
    // resistance does not apply (only admins reach this endpoint).
    try {
      await users.getUser(input.email as string);
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
  async sendLink(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;

    const cc = useControllerContext();
    const wfConfig = await cc.instantiate(MoostAuthWorkflowConfig);
    const config = wfConfig.config;
    // Runtime TTL — `@StepTTL` resolves at class-definition time, so we attach
    // `expires` to the outlet result (MoostWf only overrides when `@StepTTL`).
    return {
      ...outletEmail(ctx.email as string, "invite.magicLink", {
        ...(ctx.roles && { roles: ctx.roles }),
        expiresAtMs: config.inviteTokenTtlMs,
      }),
      expires: Date.now() + config.inviteTokenTtlMs,
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

    const cc = useControllerContext();
    const [users, auth, config, wfConfig] = await Promise.all([
      cc.instantiate(UserService),
      cc.instantiate(AuthCredential),
      cc.instantiate(MoostAuthConfig),
      cc.instantiate(MoostAuthWorkflowConfig),
    ]);

    const prepareUser = wfConfig.config.prepareUser;
    const extras = prepareUser
      ? await prepareUser({ email: ctx.email, roles: ctx.roles ?? [] })
      : undefined;

    try {
      await users.createUser(ctx.email, input.newPassword as string, extras);
    } catch (err) {
      translatePasswordSetError(err);
    }
    await users.activateAccount(ctx.email);
    // Role-application hook is intentionally not wired here in 6.5b — the
    // workflow context still carries `ctx.roles` so consumers extending the
    // controller can react to it via a spy / post-step interceptor.
    const issue = await auth.issue(ctx.email);
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(config, ctx.email, issue),
      cookies: buildFinishedCookies(config, issue),
    });
    return undefined;
  }
}
