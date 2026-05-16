/**
 * Unit coverage for `mergeInviteOpts`.
 *
 * The deep-merge is hand-rolled (one `{ ...defaults, ...input }` per nested
 * group). These tests pin the contract that runtime-relevant defaults survive
 * a partial input — without this guarantee, schema conditions that read
 * `ctx.opts.<group>.<flag>` after `inviteInit` would NPE on missing nested
 * keys.
 *
 * Each test asserts a specific WHY: "if a consumer overrides one nested key,
 * sibling defaults must still be present at runtime." That intent is broken
 * the moment someone replaces `{ ...defaults, ...input }` with `input` (or
 * `?? defaults`) for any group — which is exactly the regression this file
 * guards against.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { InviteForm } from "../atscript/models/forms.as.js";
import { parseInviteRoles } from "../workflows/invite.workflow";
import { DEFAULT_INVITE_TOKEN_TTL_MS, mergeInviteOpts } from "../workflows/invite.workflow.options";

describe("mergeInviteOpts — defaults survive partial input", () => {
  it("undefined input → every nested group is populated with its full defaults", () => {
    const opts = mergeInviteOpts();
    expect(opts.adminForm.collectFirstName).toBe(true);
    expect(opts.adminForm.collectLastName).toBe(true);
    expect(opts.adminForm.collectRoles).toBe(true);
    expect(opts.send.mode).toBe("email");
    expect(opts.send.tokenTtlMs).toBe(DEFAULT_INVITE_TOKEN_TTL_MS);
    expect(opts.accept.alreadyAcceptedRedirectUrl).toBe("/login");
    expect(opts.accept.freshLoginRequired).toBe(false);
    expect(opts.accept.loginUrl).toBe("/login");
    expect(opts.accept.showConfirmation).toBe(true);
    expect(opts.accept.confirmationMessage).toBe("Your account has been created.");
    expect(opts.cancellation.allowed).toBe(true);
    expect(opts.audit.enabled).toBe(true);
  });

  it("partial adminForm override (collectRoles:false) keeps sibling defaults", () => {
    // Regression: a naive merge like `adminForm: opts.adminForm ?? defaults`
    // would drop `collectFirstName` / `collectLastName`, breaking the admin
    // form's first/last-name capture for every consumer who flips one flag.
    const opts = mergeInviteOpts({ adminForm: { collectRoles: false } });
    expect(opts.adminForm.collectRoles).toBe(false);
    expect(opts.adminForm.collectFirstName).toBe(true);
    expect(opts.adminForm.collectLastName).toBe(true);
  });

  it("partial send override (tokenTtlMs only) keeps mode default 'email'", () => {
    // The schema's `inviteSelectSendMode` step gates on `opts.send.mode ===
    // 'choice'` — silently flipping mode to `undefined` would short-circuit
    // the send-mode picker for consumers who only tuned the TTL.
    const opts = mergeInviteOpts({ send: { tokenTtlMs: 1000 } });
    expect(opts.send.tokenTtlMs).toBe(1000);
    expect(opts.send.mode).toBe("email");
  });

  it("partial accept override (freshLoginRequired:true) keeps loginUrl / confirmation defaults", () => {
    // The `inviteFreshLoginFinish` step issues a redirect to
    // `opts.accept.loginUrl` — dropping it would 500 the workflow.
    const opts = mergeInviteOpts({ accept: { freshLoginRequired: true } });
    expect(opts.accept.freshLoginRequired).toBe(true);
    expect(opts.accept.loginUrl).toBe("/login");
    expect(opts.accept.alreadyAcceptedRedirectUrl).toBe("/login");
    expect(opts.accept.showConfirmation).toBe(true);
    expect(opts.accept.confirmationMessage).toBe("Your account has been created.");
  });

  it("partial cancellation override (allowed:false) does not leak into other groups", () => {
    const opts = mergeInviteOpts({ cancellation: { allowed: false } });
    expect(opts.cancellation.allowed).toBe(false);
    // Sibling groups untouched.
    expect(opts.adminForm.collectRoles).toBe(true);
    expect(opts.send.mode).toBe("email");
    expect(opts.audit.enabled).toBe(true);
  });

  it("partial audit override (enabled:false) keeps other groups' defaults intact", () => {
    const opts = mergeInviteOpts({ audit: { enabled: false } });
    expect(opts.audit.enabled).toBe(false);
    expect(opts.cancellation.allowed).toBe(true);
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
      adminForm: { collectFirstName: false, collectLastName: false, collectRoles: false },
      send: { mode: "shareableLink", tokenTtlMs: 5000 },
      accept: {
        alreadyAcceptedRedirectUrl: "/welcome",
        freshLoginRequired: true,
        loginUrl: "/sign-in",
        showConfirmation: false,
        confirmationMessage: "Welcome aboard.",
      },
      cancellation: { allowed: false },
      audit: { enabled: false },
    });
    expect(opts.adminForm).toEqual({
      collectFirstName: false,
      collectLastName: false,
      collectRoles: false,
    });
    expect(opts.send).toEqual({ mode: "shareableLink", tokenTtlMs: 5000 });
    expect(opts.accept).toEqual({
      alreadyAcceptedRedirectUrl: "/welcome",
      freshLoginRequired: true,
      loginUrl: "/sign-in",
      showConfirmation: false,
      confirmationMessage: "Welcome aboard.",
    });
    expect(opts.cancellation.allowed).toBe(false);
    expect(opts.audit.enabled).toBe(false);
  });
});
