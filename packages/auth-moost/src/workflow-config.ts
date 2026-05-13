import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Injectable } from "moost";

import type { EmailSender } from "./email";
import type { BuildMagicLinkUrl } from "./magic-link";

// biome-ignore lint/suspicious/noExplicitAny: form types are user-supplied; we never inspect the field shape here
type AnyAtscriptType = TAtscriptAnnotatedType<any, any>;

/**
 * Per-form overrides. Any unset form falls back to the default model shipped
 * under `@aoothjs/auth-moost/atscript`.
 */
export interface AuthWorkflowFormsOverrides {
  loginCredentials?: AnyAtscriptType;
  mfaCode?: AnyAtscriptType;
  emailIdentifier?: AnyAtscriptType;
  setPassword?: AnyAtscriptType;
  invite?: AnyAtscriptType;
}

/**
 * Options accepted by `setupAuthWorkflows()`.
 *
 * `wfStateStore` is typed `unknown` so this package's public surface does
 * not pull `@atscript/moost-wf` into consumers' type-check at the boundary —
 * Aooth never inspects it, the 6.5b workflow steps do.
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
  forms?: AuthWorkflowFormsOverrides;
}

export interface ResolvedAuthWorkflowsConfig {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  wfStateStore: unknown;
  recoveryTokenTtlMs: number;
  inviteTokenTtlMs: number;
  mfaCodeTtlMs: number;
  workflows: { login: boolean; recovery: boolean; invite: boolean };
  forms: Required<AuthWorkflowFormsOverrides>;
}

export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;
export const DEFAULT_INVITE_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_MFA_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * DI singleton carrying the resolved workflow configuration. Populated once
 * at boot by `setupAuthWorkflows()`; 6.5b workflow steps read from
 * {@link config} via Moost DI.
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

  configure(opts: AuthWorkflowsOptions, defaults: Required<AuthWorkflowFormsOverrides>): void {
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
    const forms = opts.forms ?? {};
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
      forms: {
        loginCredentials: forms.loginCredentials ?? defaults.loginCredentials,
        mfaCode: forms.mfaCode ?? defaults.mfaCode,
        emailIdentifier: forms.emailIdentifier ?? defaults.emailIdentifier,
        setPassword: forms.setPassword ?? defaults.setPassword,
        invite: forms.invite ?? defaults.invite,
      },
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
