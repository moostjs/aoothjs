/**
 * Unit coverage for `mergeInviteOpts`.
 *
 * Post-resolver reshape (Step 2 of the InviteWorkflow refactor): `InviteWorkflowOpts`
 * is infrastructure-only — magic-link TTL, pincode timers/length, and form
 * schemas. Policy fields (`adminForm`, `send.mode`, `accept`, `cancellation`,
 * `audit`, `mfa.issuer`) moved off opts to `resolveXxx(ctx)` getters. These
 * tests pin the contract that infra defaults survive a partial input —
 * without this guarantee, step bodies reading `this.opts.<group>.<flag>`
 * would NPE on missing nested keys.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { InviteForm } from "../atscript/models/forms.as";
import { parseInviteRoles } from "../workflows/invite.workflow";
import { DEFAULT_INVITE_TOKEN_TTL_MS, mergeInviteOpts } from "../workflows/invite.workflow.options";

describe("mergeInviteOpts — defaults survive partial input", () => {
  it("undefined input → every nested group is populated with its full defaults", () => {
    const opts = mergeInviteOpts();
    expect(opts.send.tokenTtlMs).toBe(DEFAULT_INVITE_TOKEN_TTL_MS);
    expect(opts.mfa.pincodeTtlMs).toBe(5 * 60 * 1000);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);
    expect(opts.mfa.pincodeLength).toBe(6);
  });

  it("partial send override (tokenTtlMs only) is honoured", () => {
    // The `invite-send-email` step uses `this.opts.send.tokenTtlMs` as the
    // magic-link expiry. Dropping it would lose the consumer's setting.
    const opts = mergeInviteOpts({ send: { tokenTtlMs: 1000 } });
    expect(opts.send.tokenTtlMs).toBe(1000);
  });

  it("partial mfa override (pincodeLength only) keeps the other mfa defaults", () => {
    const opts = mergeInviteOpts({ mfa: { pincodeLength: 4 } });
    expect(opts.mfa.pincodeLength).toBe(4);
    expect(opts.mfa.pincodeTtlMs).toBe(5 * 60 * 1000);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);
  });

  it("parseInviteRoles: trims, drops empties, dedupes", () => {
    // The string[] form input flows through this normalizer before reaching
    // the user record / email metadata — guard the contract end-to-end.
    expect(parseInviteRoles(undefined)).toEqual([]);
    expect(parseInviteRoles([])).toEqual([]);
    expect(parseInviteRoles(["a", "b"])).toEqual(["a", "b"]);
    expect(parseInviteRoles(["  a  ", "a", "", "b"])).toEqual(["a", "b"]);
  });

  it("forms group: default invite is the shipped form; consumer override wins", () => {
    expect(mergeInviteOpts({}).forms.invite).toBe(InviteForm);
    const MyForm = { __is_atscript_annotated_type: true } as unknown as TAtscriptAnnotatedType;
    expect(mergeInviteOpts({ forms: { invite: MyForm } }).forms.invite).toBe(MyForm);
  });

  it("explicit overrides beat defaults (no accidental defaulting)", () => {
    // Without this guard, `{ ...defaults, ...input }` could be silently
    // flipped to `{ ...input, ...defaults }` and the defaults would always
    // win — disabling consumer configuration.
    const opts = mergeInviteOpts({
      send: { tokenTtlMs: 5000 },
      mfa: { pincodeTtlMs: 1000, pincodeResendTimeoutMs: 500, pincodeLength: 8 },
    });
    expect(opts.send).toEqual({ tokenTtlMs: 5000 });
    expect(opts.mfa).toEqual({
      pincodeTtlMs: 1000,
      pincodeResendTimeoutMs: 500,
      pincodeLength: 8,
    });
  });
});
