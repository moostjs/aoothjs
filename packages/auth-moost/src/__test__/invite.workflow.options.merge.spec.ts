/**
 * Unit coverage for `mergeInviteOpts`.
 *
 * Post-AuthOpts reshape: `InviteWorkflowOpts` is forms-only. Magic-link TTL,
 * pincode timers/length, and TOTP issuer moved onto the shared `AuthOpts`
 * provider. The remaining contract this file pins is the form-schema replacement
 * surface — without it, step bodies reading `this.opts.forms.<form>` would NPE
 * on missing nested keys when a consumer supplies a partial `forms` map.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { InviteForm } from "../atscript/models/forms.as";
import { parseInviteRoles } from "../workflows/invite.workflow";
import { mergeInviteOpts } from "../workflows/invite.workflow.options";

describe("mergeInviteOpts — defaults survive partial input", () => {
  it("undefined input → forms group is populated with its full defaults", () => {
    const opts = mergeInviteOpts();
    expect(opts.forms.invite).toBe(InviteForm);
    expect(opts.forms.setPassword).toBeTruthy();
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
});
