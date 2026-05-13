import { describe, expect, it } from "vite-plus/test";

import {
  EmailIdentifierForm,
  InviteForm,
  LoginCredentialsForm,
  MfaCodeForm,
  SetPasswordForm,
} from "../atscript/index";
import type { EmailSender } from "../email";
import type { BuildMagicLinkUrl } from "../magic-link";
import {
  type AuthWorkflowFormsOverrides,
  type AuthWorkflowsOptions,
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  MoostAuthWorkflowConfig,
} from "../workflow-config";

const noopSender: EmailSender = { send: async () => undefined };
const noopBuildUrl: BuildMagicLinkUrl = (_kind, token) => `https://x.test/${token}`;
const fakeStore = { id: "fake-wfstate-store" };

const baseDefaults: Required<AuthWorkflowFormsOverrides> = {
  loginCredentials: LoginCredentialsForm,
  mfaCode: MfaCodeForm,
  emailIdentifier: EmailIdentifierForm,
  setPassword: SetPasswordForm,
  invite: InviteForm,
};

const baseOpts: AuthWorkflowsOptions = {
  emailSender: noopSender,
  buildMagicLinkUrl: noopBuildUrl,
  wfStateStore: fakeStore,
};

function configured(opts: AuthWorkflowsOptions): MoostAuthWorkflowConfig {
  const c = new MoostAuthWorkflowConfig();
  c.configure(opts, baseDefaults);
  return c;
}

describe("MoostAuthWorkflowConfig.configure", () => {
  it("applies all defaults when only required fields are supplied", () => {
    const cfg = configured(baseOpts).config;

    expect(cfg.emailSender).toBe(noopSender);
    expect(cfg.buildMagicLinkUrl).toBe(noopBuildUrl);
    expect(cfg.wfStateStore).toBe(fakeStore);

    expect(cfg.recoveryTokenTtlMs).toBe(DEFAULT_RECOVERY_TOKEN_TTL_MS);
    expect(cfg.inviteTokenTtlMs).toBe(DEFAULT_INVITE_TOKEN_TTL_MS);
    expect(cfg.mfaCodeTtlMs).toBe(DEFAULT_MFA_CODE_TTL_MS);

    expect(cfg.workflows).toEqual({ login: true, recovery: true, invite: true });

    expect(cfg.forms.loginCredentials).toBe(LoginCredentialsForm);
    expect(cfg.forms.mfaCode).toBe(MfaCodeForm);
    expect(cfg.forms.emailIdentifier).toBe(EmailIdentifierForm);
    expect(cfg.forms.setPassword).toBe(SetPasswordForm);
    expect(cfg.forms.invite).toBe(InviteForm);
  });

  it("uses overrides over defaults", () => {
    // Stand-in for a user-supplied annotated type. Identity is all we test.
    const CustomLogin = { __is_atscript_annotated_type: true } as const;
    const cfg = configured({
      ...baseOpts,
      recoveryTokenTtlMs: 60_000,
      inviteTokenTtlMs: 7_200_000,
      mfaCodeTtlMs: 30_000,
      workflows: { login: false, invite: false },
      // biome-ignore lint/suspicious/noExplicitAny: test override using non-annotated stand-in
      forms: { loginCredentials: CustomLogin as any },
    }).config;

    expect(cfg.recoveryTokenTtlMs).toBe(60_000);
    expect(cfg.inviteTokenTtlMs).toBe(7_200_000);
    expect(cfg.mfaCodeTtlMs).toBe(30_000);
    expect(cfg.workflows).toEqual({ login: false, recovery: true, invite: false });
    expect(cfg.forms.loginCredentials).toBe(CustomLogin);
    expect(cfg.forms.mfaCode).toBe(MfaCodeForm);
  });

  it("throws on missing emailSender / buildMagicLinkUrl / wfStateStore", () => {
    expect(() =>
      configured({ ...baseOpts, emailSender: undefined as unknown as EmailSender }),
    ).toThrow(/emailSender\.send/);
    expect(() =>
      configured({ ...baseOpts, buildMagicLinkUrl: undefined as unknown as BuildMagicLinkUrl }),
    ).toThrow(/buildMagicLinkUrl/);
    expect(() => configured({ ...baseOpts, wfStateStore: null })).toThrow(/wfStateStore/);
  });

  it("rejects TTLs below 1000ms or non-finite", () => {
    expect(() => configured({ ...baseOpts, recoveryTokenTtlMs: 500 })).toThrow(
      /recoveryTokenTtlMs/,
    );
    expect(() => configured({ ...baseOpts, inviteTokenTtlMs: 0 })).toThrow(/inviteTokenTtlMs/);
    expect(() => configured({ ...baseOpts, mfaCodeTtlMs: Number.POSITIVE_INFINITY })).toThrow(
      /mfaCodeTtlMs/,
    );
    expect(() => configured({ ...baseOpts, mfaCodeTtlMs: Number.NaN })).toThrow(/mfaCodeTtlMs/);
  });

  it("throws when read before configure()", () => {
    const c = new MoostAuthWorkflowConfig();
    expect(() => c.config).toThrow(/not configured/);
  });
});
