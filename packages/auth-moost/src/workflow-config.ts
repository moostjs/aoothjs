import type { BuildMagicLinkUrl, EmailSender } from "@aoothjs/auth";
import { Injectable } from "moost";

/**
 * Input passed to {@link AuthWorkflowsOptions.prepareUser}: the validated
 * invite-step `email` plus the parsed `roles[]` array the workflow already
 * computed (empty when the admin did not specify any roles).
 */
export interface InvitePrepareUserInput {
  email: string;
  roles: string[];
}

/**
 * `wfStateStore` is typed `unknown` so this package's public surface does not
 * pull `@atscript/moost-wf` into consumers' type-check at the boundary —
 * Aooth never inspects it, the workflow steps do.
 */
export interface AuthWorkflowsOptions {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  wfStateStore: unknown;
  recoveryTokenTtlMs?: number;
  inviteTokenTtlMs?: number;
  mfaCodeTtlMs?: number;
  workflows?: {
    login?: boolean;
    recovery?: boolean;
    invite?: boolean;
  };
  /**
   * Called by `InviteWorkflow.accept` immediately before
   * `userService.createUser` to populate consumer-specific required user
   * fields (e.g. `tenantId`) without subclassing the user store. The returned
   * object is forwarded as the `extras` argument to `createUser`.
   */
  prepareUser?: (
    input: InvitePrepareUserInput,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
  /**
   * Resolves the recovery-step `email` input to the `username` (user-id) that
   * `UserService.getUser` expects. Apps whose user model separates `username`
   * and `email` MUST provide this — otherwise `RecoveryWorkflow.requestRecovery`
   * falls back to `userService.getUser(email)`, which delegates to
   * `userStore.findByUsername(email)` and silently misses for any user whose
   * `username !== email`. Return `null` when no user matches that email.
   */
  emailToUserId?: (email: string) => Promise<string | null> | string | null;
}

export interface ResolvedAuthWorkflowsConfig {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  wfStateStore: unknown;
  recoveryTokenTtlMs: number;
  inviteTokenTtlMs: number;
  mfaCodeTtlMs: number;
  workflows: { login: boolean; recovery: boolean; invite: boolean };
  prepareUser?: (
    input: InvitePrepareUserInput,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
  emailToUserId?: (email: string) => Promise<string | null> | string | null;
}

export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;
export const DEFAULT_INVITE_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_MFA_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * DI singleton carrying the resolved workflow configuration. Populated once
 * at boot by `setupAuthWorkflows()`; workflow steps read from {@link config}
 * via Moost DI.
 */
@Injectable()
export class MoostAuthWorkflowConfig {
  #cfg: ResolvedAuthWorkflowsConfig | null = null;

  get config(): ResolvedAuthWorkflowsConfig {
    if (!this.#cfg) {
      throw new Error(
        "MoostAuthWorkflowConfig not configured. Call setupAuthWorkflows(moost, ...) first.",
      );
    }
    return this.#cfg;
  }

  configure(opts: AuthWorkflowsOptions): void {
    if (!opts.emailSender || typeof opts.emailSender.send !== "function") {
      throw new Error("setupAuthWorkflows: `emailSender.send` is required and must be a function");
    }
    if (typeof opts.buildMagicLinkUrl !== "function") {
      throw new Error("setupAuthWorkflows: `buildMagicLinkUrl` must be a function");
    }
    if (opts.wfStateStore === undefined || opts.wfStateStore === null) {
      throw new Error(
        "setupAuthWorkflows: `wfStateStore` is required — pass an AsWfStore (or other WfStateStore) instance",
      );
    }

    const wf = opts.workflows ?? {};
    this.#cfg = {
      emailSender: opts.emailSender,
      buildMagicLinkUrl: opts.buildMagicLinkUrl,
      wfStateStore: opts.wfStateStore,
      recoveryTokenTtlMs: ttlOrDefault(
        "recoveryTokenTtlMs",
        opts.recoveryTokenTtlMs,
        DEFAULT_RECOVERY_TOKEN_TTL_MS,
      ),
      inviteTokenTtlMs: ttlOrDefault(
        "inviteTokenTtlMs",
        opts.inviteTokenTtlMs,
        DEFAULT_INVITE_TOKEN_TTL_MS,
      ),
      mfaCodeTtlMs: ttlOrDefault("mfaCodeTtlMs", opts.mfaCodeTtlMs, DEFAULT_MFA_CODE_TTL_MS),
      workflows: {
        login: wf.login ?? true,
        recovery: wf.recovery ?? true,
        invite: wf.invite ?? true,
      },
      prepareUser: opts.prepareUser,
      emailToUserId: opts.emailToUserId,
    };
  }
}

function ttlOrDefault(name: string, value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value < 1000) {
    throw new Error(`setupAuthWorkflows: \`${name}\` must be a finite number >= 1000 (ms)`);
  }
  return value;
}
