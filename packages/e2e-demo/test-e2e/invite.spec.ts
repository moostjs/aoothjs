/**
 * P0 Playwright coverage for the invite family (auth/invite/start only —
 * the cancel + resend sub-workflows were dropped in 6ff3efb). Maps to
 * USER_STORIES.md §5 rows tagged Tier=P0:
 *
 *   WF-INVITE-001  variant `email-no-roles` — happy path
 *   WF-INVITE-005  variant `roles-profile`  — role picker rendered
 *
 * Driving model. Admin pre-auth + the rendered admin-side forms run through
 * the SPA (`/wf?id=…`) — that's where the variant-shaped DOM lives. We
 * assert the rendered fields, then assert on the server response the
 * outlet returns (`{sent:true,outlet:"email"}` envelope).
 *
 * Pre-auth: drive `auth/login/flow` (variant `minimal`) via the SPA so
 * the auto-login finish writes the `aooth_access` cookie into the
 * browser context — subsequent same-origin `/auth/trigger` POSTs (whether
 * fired by `<AsWfForm>` or by `page.request`) carry the cookie.
 */
import { expect, test } from "@playwright/test";
import type { Page, Response } from "@playwright/test";

import type { APIRequestContext } from "@playwright/test";

import {
  clickAction,
  fillField,
  loginViaUi,
  rewriteToBaseUrl,
  submitForm,
  uniqueEmail,
  USERS,
  waitForEmail,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

/**
 * Resilient reset wrapping the harness one. The demo's `__test/reset` is
 * flaky under repeated invocation (occasional `FOREIGN KEY constraint
 * failed` 500 between consecutive tests). Retry once after a short pause —
 * matches the operator's observation that a 1-2s wait clears the FK
 * state. Pre-existing infra issue; out of scope for these P0 specs.
 */
async function resetAppResilient(request: APIRequestContext): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await request.post("/__test/reset");
    if (res.status() === 201) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  const final = await request.post("/__test/reset");
  expect(final.status(), "reset endpoint mounted (run with DEMO_MODE=test)").toBe(201);
}

/** Wait for the next `/auth/trigger` JSON response and return its parsed body. */
async function nextTriggerResponse(
  page: Page,
  predicate: (body: Record<string, unknown>) => boolean,
  timeoutMs = 5000,
): Promise<Record<string, unknown>> {
  const res: Response = await page.waitForResponse(
    async (r) => {
      if (!r.url().includes("/auth/trigger") || r.request().method() !== "POST") return false;
      try {
        const body = (await r.json()) as Record<string, unknown>;
        return predicate(body);
      } catch {
        return false;
      }
    },
    { timeout: timeoutMs },
  );
  return (await res.json()) as Record<string, unknown>;
}

test.describe("WF-INVITE — auth.invite family (P0)", () => {
  test.beforeEach(async ({ request }) => {
    await resetAppResilient(request);
  });

  // ── WF-INVITE-001 ────────────────────────────────────────────────────────
  test("WF-INVITE-001 admin invites new email → invitee redeems → tokens", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-001");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    const sentEnvelope = await sentPromise;
    expect(sentEnvelope.outlet).toBe("email");

    // Pick the captured magic-link email for this run.
    const magic = await waitForEmail(
      request,
      (e) => e.kind === "invite.magicLink" && e.recipient === inviteeEmail,
    );
    expect(magic.url, "magic-link email must carry a resume url").toBeTruthy();
    expect(magic.url).toContain("wfs=");

    // Invitee resumes via the SPA — router rewrites `/signup?wfs=…` (and any
    // pretty path the magic-link uses) onto `/wf?id=auth.invite&wfs=…`, which
    // WfPage forwards to AsWfForm as `initialToken`.
    const resumeUrl = rewriteToBaseUrl(magic.url as string, baseURL ?? "");
    // Fresh browser context to drop the admin cookies — invitee is anonymous.
    const ctx = await page.context().browser()!.newContext();
    const inviteePage = await ctx.newPage();
    await inviteePage.goto(resumeUrl);

    // Invitee SetPasswordForm pause.
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    // Pin the invite-specific welcome heading + intro copy. The bundled
    // phantom paragraphs read `ctx.password.heading` / `ctx.password.intro`
    // set by `create-password-form` before the pause.
    await expect(inviteePage.getByText("Welcome — set your password")).toBeVisible();
    await expect(inviteePage.getByText(/activate your account/i)).toBeVisible();
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    await inviteePage.locator("button.as-submit-btn, button[type=submit]").first().click();

    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.locator("pre").first()).toContainText("accessToken");
    await ctx.close();
  });

  // ── WF-INVITE-005 ────────────────────────────────────────────────────────
  test("WF-INVITE-005 role-whitelist variant `roles-profile` renders role field", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "roles-profile"));
    await expect(page.locator('[name="email"]')).toBeVisible();

    // `collectRoles: true` on the variant ⇒ `roles?: string[]` renders as an
    // `as-multi-select-field` (not a native `[name="roles"]` input). The
    // field is structurally present when the label "Roles" is visible AND a
    // multi-select container is in the DOM.
    await expect(page.locator(".as-field-label", { hasText: "Roles" })).toBeVisible();
    await expect(page.locator(".as-multi-select-field")).toHaveCount(1);
  });
});

/**
 * P1 coverage for the invite family. Maps to USER_STORIES.md §5 rows tagged
 * Tier=P1:
 *
 *   WF-INVITE-002  variant `email-no-roles`     — invite existing user → 409
 *   WF-INVITE-006  variant `roles-profile`      — role not in whitelist → form error
 *
 * The `t1_redeemed` seed has `username = email = t1_redeemed@example.com`,
 * which is the structural prerequisite for `loadUserOrNull(email)` to find
 * it via `findByUsername(email)`. -002 hits it.
 *
 * Error surface: AsWfForm forwards trigger failures to the `@error` slot →
 * `WfPage.vue` paints `err.message` inside `div.scope-error` near the form.
 * That's the inline error contract for every "form re-renders with error"
 * row in §5.3.
 */
test.describe("WF-INVITE — auth.invite family (P1)", () => {
  test.beforeEach(async ({ request }) => {
    await resetAppResilient(request);
  });

  // ── WF-INVITE-002 ────────────────────────────────────────────────────────
  // BRANCH: `inviteAdminInviteForm` → `loadUserOrNull(email)` finds the
  // already-accepted seed user (`t1_redeemed@example.com` — username equals
  // email, so the `findByUsername` lookup resolves) → default
  // `duplicateCheck` returns 'reject' → step calls
  // `wf.requireInput({ errors: { email: 'User already exists' } })`. The wf
  // engine re-pauses the same step under the same wfs token; the response is
  // a 201 `inputRequired` envelope with `context.errors.email` populated.
  // AsWfForm re-renders the same form with the per-field error attached.
  test("WF-INVITE-002 admin invites already-redeemed user → inline email error, form re-renders", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    await fillField(page, "email", "t1_redeemed@example.com");
    // requireInput envelope: `{ inputRequired: { payload, context: { errors:
    // { email: 'User already exists' }, ... } }, wfs }`.
    const errorPromise = nextTriggerResponse(
      page,
      (b) => {
        const ir = b.inputRequired as Record<string, unknown> | undefined;
        const ctxObj = (ir?.context ?? {}) as Record<string, unknown>;
        const errs = (ctxObj.errors ?? {}) as Record<string, unknown>;
        return typeof errs.email === "string" && /already exists/i.test(errs.email);
      },
      10_000,
    );
    await submitForm(page);
    const body = await errorPromise;
    const ir = body.inputRequired as Record<string, unknown>;
    const ctxObj = ir.context as Record<string, unknown>;
    const errs = ctxObj.errors as Record<string, string>;
    expect(errs.email).toMatch(/User already exists/i);
    // Form re-renders — same step paused under the same wfs token, email
    // field still mounted so the user can correct and retry.
    await expect(page.locator('[name="email"]')).toBeVisible();
  });

  // ── WF-INVITE-006 ────────────────────────────────────────────────────────
  // BRANCH: `inviteAdminInviteForm` → role validation — `validateAdminInput`
  // intersects submitted roles against `ctx.admin.availableRoles` (sourced from
  // `getAvailableRoles()` which returns `['admin','editor','viewer','member']`
  // in the demo). Submitting `'superuser'` triggers
  // `wf.requireInput({ errors: { roles: 'Invalid role' } })`.
  //
  // The roles widget is a `select`-style multi-picker that only offers the
  // whitelist — so we can't pick `superuser` through the UI. We intercept
  // the outgoing `/auth/trigger` POST and inject the bad role into the
  // payload, then assert the server's `requireInput` errors envelope.
  test("WF-INVITE-006 admin submits role outside whitelist → form error", async ({ page }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "roles-profile"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    // Inject `roles: ['superuser']` into the InviteForm submission. The UI
    // multi-select only offers whitelisted options — this intercept bypasses
    // the widget so the server-side validator branch fires. AsWfForm wraps
    // the submitted form values under `input.formData`.
    await page.route("**/auth/trigger", async (route) => {
      const req = route.request();
      if (req.method() !== "POST") return route.continue();
      const raw = req.postData();
      if (!raw) return route.continue();
      try {
        const body = JSON.parse(raw) as Record<string, unknown>;
        const input = (body.input ?? {}) as Record<string, unknown>;
        const formData = (input.formData ?? {}) as Record<string, unknown>;
        if (typeof formData.email === "string") {
          formData.roles = ["superuser"];
          input.formData = formData;
          body.input = input;
          return route.continue({ postData: JSON.stringify(body) });
        }
      } catch {
        // fallthrough
      }
      return route.continue();
    });

    await fillField(page, "email", uniqueEmail("invite-006"));
    // requireInput envelope: `{ inputRequired: { payload, transport, context: {
    // errors: { roles: 'Invalid role' }, …passContext } } }`.
    const errorPromise = nextTriggerResponse(
      page,
      (b) => {
        const ir = b.inputRequired as Record<string, unknown> | undefined;
        const ctxObj = (ir?.context ?? {}) as Record<string, unknown>;
        const errs = (ctxObj.errors ?? {}) as Record<string, unknown>;
        return typeof errs.roles === "string" && /invalid role/i.test(errs.roles);
      },
      10_000,
    );
    await submitForm(page);
    const body = await errorPromise;
    const ir = body.inputRequired as Record<string, unknown>;
    const ctxObj = ir.context as Record<string, unknown>;
    const errs = ctxObj.errors as Record<string, string>;
    expect(errs.roles).toMatch(/Invalid role/i);
    // The `requireInput` envelope keeps the form mounted — re-prompt for input.
    await expect(page.locator('[name="email"]')).toBeVisible();
  });
});

// ─── P2 STORIES ───
/**
 * P2 coverage for the invite family. Maps to USER_STORIES.md §5 rows tagged
 * Tier=P2:
 *
 *   WF-INVITE-010  variant `idempotent-redirect`     — already-accepted link click → 2-button finish
 *   WF-INVITE-018  variant `email-no-roles`          — `duplicateCheck='allow'` override (FIXME)
 *   WF-INVITE-020  variant `confirmation-message`    — `showConfirmation: true` finish message
 *
 * Same error-surface contract as P1: AsWfForm forwards trigger failures (incl.
 * the 410 on resume of a now-expired token) to `@error` → WfPage paints
 * `err.message` inside `div.scope-error`. AsWfFinish renders manual-mode
 * envelopes as `button.as-wf-finish-primary` (label as text) + zero-or-more
 * `button.as-wf-finish-option` (label as text), with the message painted under
 * `div.as-wf-finish-message[data-level=…]`.
 */
test.describe("WF-INVITE — auth.invite family (P2)", () => {
  test.beforeEach(async ({ request }) => {
    await resetAppResilient(request);
  });

  // ── WF-INVITE-010 ────────────────────────────────────────────────────────
  // BRANCH: §5.3 names this as "second click on the SAME magic link after the
  // invitee has already redeemed → 2-button idempotent finish (primary: 'Go
  // to sign-in', secondary: 'Request a new invite').
  //
  // BACKGROUND on the workaround. The first redemption completes the
  // wf-state; the moost-wf store evicts finished rows. A second click on
  // the SAME magic link resumes against a missing wf-state row and the
  // store responds 410 BEFORE `inviteCheckPendingInvitation` re-enters —
  // so the original `inviteIdempotentRedirect` step is structurally
  // unreachable on a same-token re-click (see prior fixme notes).
  //
  // Workaround: the demo's `buildMagicLinkUrl` embeds `&uid=<userId>` in
  // the magic-link URL; `WfPage.vue`'s `onError` handler fetches
  // `/auth/invite/post-redemption?uid=…` when a wf request fails AND `uid`
  // is present in the URL. The bundled `AuthController` route looks up
  // the user via `UserService.getUser(uid)` and returns the same envelope
  // shape `inviteIdempotentRedirect` would have produced when the user is
  // no longer `pendingInvitation`; the SPA renders it through
  // `<AsWfFinish>` so the two paths are visually identical to the user.
  test("WF-INVITE-010 second click on accepted invite → 2-button idempotent finish", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "idempotent-redirect"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-010");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    await sentPromise;

    // Pick the captured magic-link email — assert `uid=` is in the URL so
    // the fallback can resolve the invitee. This also documents the
    // wire-shape change (Piece E in the workaround).
    const magic = await waitForEmail(
      request,
      (e) => e.kind === "invite.magicLink" && e.recipient === inviteeEmail,
    );
    expect(magic.url, "magic-link email must carry a resume url").toBeTruthy();
    expect(magic.url).toContain("wfs=");
    expect(magic.url, "magic-link must embed uid for the post-redemption fallback").toContain(
      `uid=${encodeURIComponent(inviteeEmail)}`,
    );

    const resumeUrl = rewriteToBaseUrl(magic.url as string, baseURL ?? "");

    // First click: invitee redeems normally (mirrors WF-INVITE-001). Use a
    // fresh browser context so the admin's cookies don't leak in.
    const ctx = await page.context().browser()!.newContext();
    const inviteePage = await ctx.newPage();
    await inviteePage.goto(resumeUrl);

    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    await inviteePage.locator("button.as-submit-btn, button[type=submit]").first().click();

    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });

    // Second click: SAME magic-link URL again. Drop the post-redemption
    // cookies via a brand-new browser context so the second click is fully
    // anonymous (the first redemption auto-logged-in via cookies).
    await ctx.close();
    const ctx2 = await page.context().browser()!.newContext();
    const reclickPage = await ctx2.newPage();
    await reclickPage.goto(resumeUrl);

    // Both buttons rendered via `<AsWfFinish>` — primary + the
    // `Request a new invite` option (guaranteed by the `idempotent-redirect`
    // variant explicitly setting `accept.alreadyAcceptedRedirectUrl = '/login'`,
    // which is also the library default — kept for clarity).
    await expect(reclickPage.getByRole("button", { name: "Go to sign-in" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(reclickPage.getByRole("button", { name: "Request a new invite" })).toBeVisible();
    // Confirm the painted error UI was NOT used — the fallback short-circuits
    // it. (`onError` clears `error` on a successful side-route fetch.)
    await expect(reclickPage.locator(".scope-error")).toHaveCount(0);
    await ctx2.close();
  });

  // ── WF-INVITE-018 ────────────────────────────────────────────────────────
  // BRANCH: §5.3 — "consumer overrides `duplicateCheck` to 'allow', store-level
  // uniqueness still rejects with 409 'User already exists'". The demo's
  // `DemoInviteWorkflow.duplicateCheck()` consults a globalThis flag flipped
  // by `POST /__test/allow-duplicate-invites`; when set, it returns `'allow'`
  // so the workflow-level reject branch is skipped. The admin then drives
  // `auth.invite` against an existing seed user (`t1_redeemed@example.com`)
  // — `create-user` step calls `users.createUser(email, …)`, the store
  // throws `UserAuthError.ALREADY_EXISTS`, and the catch-block translates it
  // to a terminal `HttpError(409, "User already exists")` (not retriable —
  // the consumer explicitly opted out of the workflow-level dedupe). The
  // SPA renders the message verbatim under `.scope-error`.
  test("WF-INVITE-018 duplicateCheck='allow' override → store-level constraint still 409s", async ({
    page,
    request,
  }) => {
    // Flip the demo-side flag BEFORE we drive the workflow. The reset hook
    // in `beforeEach` zeroes the flag between tests so it doesn't leak.
    const flip = await request.post("/__test/allow-duplicate-invites");
    expect(flip.status()).toBeGreaterThanOrEqual(200);
    expect(flip.status()).toBeLessThan(300);

    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    // `t1_redeemed@example.com` is the seed user whose `username = email`,
    // so the store's `findByUsername(email)` resolves it (same target as
    // WF-INVITE-002). With duplicateCheck='allow', the form step now passes
    // and `invitePreCreateUser`'s `users.createUser` is what 409s.
    await fillField(page, "email", "t1_redeemed@example.com");
    const errorPromise = nextTriggerResponse(
      page,
      (b) => typeof b.message === "string" && /already exists|409/i.test(b.message),
      10_000,
    );
    await submitForm(page);
    const body = await errorPromise;
    expect(body.message).toMatch(/User already exists/i);
    await expect(page.locator(".scope-error")).toContainText(/User already exists/i);
    // Form re-renders — the workflow stayed on the admin invite step (the
    // 409 came from a step body, not from a validation error short-circuit).
    await expect(page.locator('[name="email"]')).toBeVisible();
  });

  // ── WF-INVITE-020 ────────────────────────────────────────────────────────
  // BRANCH: §5.3 — "`showConfirmation: true` + `confirmationMessage` → invitee
  // sees the configured success message after redemption". The
  // `confirmation-message` variant flips `showConfirmation: true` AND sets
  // `confirmationMessage: 'Your account has been created.'`.
  //
  // `inviteConfirmation` calls `finishWf({ message: { level: 'success',
  // text: opts.accept.confirmationMessage } })`; the subsequent
  // `inviteAutoLoginFinish` step now MERGES that `message` into its own
  // data envelope (instead of overwriting it as it used to) — so the SPA
  // receives both the tokens AND the configured text. WfPage's `<pre>` JSON
  // dump renders the full envelope, so we read it through the wire response
  // and the rendered DOM as a cross-check.
  test("WF-INVITE-020 showConfirmation=true → confirmation message rendered", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "confirmation-message"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-020");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    await sentPromise;

    const magic = await waitForEmail(
      request,
      (e) => e.kind === "invite.magicLink" && e.recipient === inviteeEmail,
    );
    const resumeUrl = rewriteToBaseUrl(magic.url as string, baseURL ?? "");
    const ctx = await page.context().browser()!.newContext();
    const inviteePage = await ctx.newPage();
    await inviteePage.goto(resumeUrl);

    // SetPasswordForm pause.
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    // Capture the final auto-login envelope on the wire — must carry BOTH
    // the access token AND the preserved confirmation message.
    const finishPromise = nextTriggerResponse(
      inviteePage,
      (b) => b.finished === true && b.data !== undefined,
      15_000,
    );
    await inviteePage.locator("button.as-submit-btn, button[type=submit]").first().click();
    const envelope = await finishPromise;

    expect(envelope.finished).toBe(true);
    const data = envelope.data as Record<string, unknown> | undefined;
    expect(data, "auto-login envelope must carry the issued tokens").toBeDefined();
    expect(data?.accessToken, "auto-login still fires when showConfirmation=true").toBeTruthy();
    const message = envelope.message as { level?: string; text?: string } | undefined;
    expect(message, "confirmation message preserved through autoLoginFinish").toBeDefined();
    expect(message?.text).toBe("Your account has been created.");
    expect(message?.level).toBe("success");

    // The rendered `<pre>` JSON dump on WfPage mirrors the wire envelope.
    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.locator("pre").first()).toContainText(
      "Your account has been created.",
    );
    await expect(inviteePage.locator("pre").first()).toContainText("accessToken");
    await ctx.close();
  });
});

// ─── MFA-ENROLLMENT INVITE STORIES (PW MFA coverage PR) ────────────────────
//
// These pin the optional-mode invite-tail enrollment ergonomics shipped by
// PR7-2 (which fixed a linear-schema bug where useDifferentMethod from
// EnrollConfirmForm could activate the account with no MFA enrolled even
// under required mode) end-to-end through the SPA. Vitest WF-INVITE-12/15/16/17
// covers the wire layer. These add browser coverage so SPA-side regressions
// in action-button visibility / form-scope re-render after action dispatch
// surface here before they bite real users.
test.describe("WF-INVITE — auth.invite family (MFA enrollment, PW MFA coverage)", () => {
  test.beforeEach(async ({ request }) => {
    await resetAppResilient(request);
  });

  /**
   * BRANCH: `optional` mode + 3-transport menu on the invite tail → after
   * password-set the workflow pauses on EnrollPickMethodForm. Clicking `skip`
   * (visible only when `enrollMode === 'optional'`) short-circuits the
   * enrolment loop; the invitee gets activated + tokens, with `mfa.methods`
   * still empty. A regression that ungated skip in required mode would let
   * invitees bypass forced MFA; a regression that wired skip into Phase 2
   * (address) would persist a covert unconfirmed row before the loop exits.
   * This is the SPA-layer pin for the vitest WF-INVITE-16 contract.
   */
  test("WF-INVITE-021 invite-tail optional + skip from EnrollPickMethodForm → activated, no mfa enrolled", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "invite-mfa-optional-full"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-021");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    await sentPromise;

    const magic = await waitForEmail(
      request,
      (e) => e.kind === "invite.magicLink" && e.recipient === inviteeEmail,
    );
    const resumeUrl = rewriteToBaseUrl(magic.url as string, baseURL ?? "");
    const ctx = await page.context().browser()!.newContext();
    const inviteePage = await ctx.newPage();
    await inviteePage.goto(resumeUrl);

    // SetPasswordForm pause first.
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    await submitForm(inviteePage);

    // EnrollPickMethodForm pause — `method` radio + `Skip for now` action
    // visible because variant set mfaMode='optional'. Click skip.
    await waitForFormInput(inviteePage, "method");
    await clickAction(inviteePage, "Skip for now");

    // Auto-login finish runs because skip leaves `ctx.aborted` false.
    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.locator("pre").first()).toContainText("accessToken");

    // Activation + no MFA enrolled — both halves of the WF-INVITE-16 contract.
    const userRes = await request.get(`/__test/user/${encodeURIComponent(inviteeEmail)}`);
    expect(userRes.status()).toBe(200);
    const userRec = (await userRes.json()) as {
      mfa: { methods: unknown[] };
      account: { active: boolean };
    };
    expect(userRec.account.active).toBe(true);
    expect(userRec.mfa.methods).toHaveLength(0);
    await ctx.close();
  });

  /**
   * BRANCH: `EnrollConfirmForm.useDifferentMethod` (totp branch — `resend`
   * is hidden when method='totp' so the only alt-action is the switch).
   * Clicking it must (a) trigger `cleanupEnrollment` so the unconfirmed
   * totp row is removed, (b) clear `ctx.enrollMethod`, (c) loop back to
   * EnrollPickMethodForm. PR7-2 fixed a regression where the linear invite
   * schema let useDifferentMethod from Phase 3 fall through to activation
   * with NO MFA enrolled even under required mode — this test pins the
   * cleanup half (the activation half is the vitest WF-INVITE-15 territory)
   * AND proves a fresh totp pick after the switch can still complete normally.
   */
  test("WF-INVITE-022 invite-tail optional + useDifferentMethod from EnrollConfirmForm (totp→sms) → loops to picker, cleanup removes totp row, sms enroll completes", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "invite-mfa-optional-full"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-022");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    await sentPromise;

    const magic = await waitForEmail(
      request,
      (e) => e.kind === "invite.magicLink" && e.recipient === inviteeEmail,
    );
    const resumeUrl = rewriteToBaseUrl(magic.url as string, baseURL ?? "");
    const ctx = await page.context().browser()!.newContext();
    const inviteePage = await ctx.newPage();
    await inviteePage.goto(resumeUrl);

    // SetPasswordForm.
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    await submitForm(inviteePage);

    // Picker → pick totp. TOTP skips the EnrollAddressForm (no address to
    // collect; secret is server-provisioned) and lands straight on
    // EnrollConfirmForm. Wait for `method` first.
    await waitForFormInput(inviteePage, "method");
    await fillField(inviteePage, "method", "totp");
    await submitForm(inviteePage);

    // EnrollConfirmForm — `code` field. Mid-flow store assertion: the
    // unconfirmed totp row was persisted by Phase 1 (proves the cleanup
    // branch below isn't a vacuous pass on a system that never wrote one).
    await waitForFormInput(inviteePage, "code");
    const before = await request.get(`/__test/user/${encodeURIComponent(inviteeEmail)}`);
    const beforeRec = (await before.json()) as {
      mfa: { methods: Array<{ name: string; confirmed: boolean }> };
    };
    expect(beforeRec.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(false);

    // useDifferentMethod — loops back to picker, cleanupEnrollment removes
    // the totp row.
    await clickAction(inviteePage, "Use a different method");
    await waitForFormInput(inviteePage, "method");

    // Cleanup proof: no totp row left.
    const mid = await request.get(`/__test/user/${encodeURIComponent(inviteeEmail)}`);
    const midRec = (await mid.json()) as {
      mfa: { methods: Array<{ name: string }> };
    };
    expect(midRec.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();

    // Now pick sms — drives EnrollAddressForm → EnrollConfirmForm (with
    // pincode side-channel). Completing this branch proves the schema
    // re-entered the loop cleanly after useDifferentMethod.
    await fillField(inviteePage, "method", "sms");
    await submitForm(inviteePage);

    await waitForFormInput(inviteePage, "address");
    const phone = "+15555550777";
    await fillField(inviteePage, "address", phone);
    await submitForm(inviteePage);

    await waitForFormInput(inviteePage, "code");
    const sms = await waitForSms(
      request,
      (e) => e.kind === "login.pincode" && (e.recipient ?? "").startsWith(phone),
    );
    expect(sms.code).toBeTruthy();
    await fillField(inviteePage, "code", sms.code);
    await submitForm(inviteePage);

    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.locator("pre").first()).toContainText("accessToken");

    // Final store state: sms confirmed, totp absent.
    const after = await request.get(`/__test/user/${encodeURIComponent(inviteeEmail)}`);
    const afterRec = (await after.json()) as {
      mfa: { methods: Array<{ name: string; confirmed: boolean }> };
    };
    expect(afterRec.mfa.methods.find((m) => m.name === "sms")?.confirmed).toBe(true);
    expect(afterRec.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();
    await ctx.close();
  });
});

// ── Phase-5 dynamic inline-consent on invite ─────────────────────────────────
//
// Mirrors WF-CONSENT-ARRAY-01 in consent.spec.ts. The `invite-terms` variant
// keys the customer `DemoConsentStore.getPendingConsents` to return a single
// required-terms descriptor → `SetPasswordForm` renders the `AsConsentArray`
// row for the dynamic `consents: string[]` field. The post-form
// `persist-consents` step batches one event per pending descriptor into one
// `DemoConsentStore.save` call, which appends to the SAME globalThis-anchored
// consent log the recovery + login flows write to.
test.describe("WF-INVITE — inline-consent on accept (Phase 5)", () => {
  test.beforeEach(async ({ request }) => {
    await resetAppResilient(request);
  });

  test("WF-INVITE-CONSENT-01: invite-terms variant → SetPasswordForm shows AsConsentArray; tick + submit → consent-log carries {id:'terms', accepted:true, version:'v1'}", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth/invite/start", "invite-terms"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-consent-01");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    await sentPromise;

    const magic = await waitForEmail(
      request,
      (e) => e.kind === "invite.magicLink" && e.recipient === inviteeEmail,
    );
    const resumeUrl = rewriteToBaseUrl(magic.url as string, baseURL ?? "");
    const ctx = await page.context().browser()!.newContext();
    const inviteePage = await ctx.newPage();
    await inviteePage.goto(resumeUrl);

    // SetPasswordForm pause — `AsConsentArray` row visible BECAUSE the
    // variant's ConsentStore returned a required terms descriptor (component
    // self-hides on empty pendingConsents).
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.getByText("I accept the Terms")).toBeVisible();
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    // First checkbox on the form is the AsConsentArray row for `terms`.
    await inviteePage.locator('input[type="checkbox"]').first().check();
    await submitForm(inviteePage);

    // Auto-login finish issues tokens — proof the workflow completed
    // through the `persist-consents` step.
    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.locator("pre").first()).toContainText("accessToken");

    // The unified consent log carries the captured event in the new shape.
    const after = await request.get(`/__test/consent-log/${encodeURIComponent(inviteeEmail)}`);
    expect(after.status()).toBe(200);
    const events = (await after.json()) as Array<{
      id: string;
      accepted: boolean;
      version?: string;
      at: number;
    }>;
    expect(events.length).toBe(1);
    expect(events[0].id).toBe("terms");
    expect(events[0].accepted).toBe(true);
    expect(events[0].version).toBe("v1");
    expect(typeof events[0].at).toBe("number");
    await ctx.close();
  });
});
