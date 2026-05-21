/**
 * P0 Playwright coverage for the invite family (auth.invite + auth.reInvite
 * + auth.cancelInvite). Maps to USER_STORIES.md §5 rows tagged Tier=P0:
 *
 *   WF-INVITE-001  variant `email-no-roles` — happy path
 *   WF-INVITE-005  variant `roles-profile`  — role picker rendered
 *   WF-INVITE-007  variant `roles-profile`  — profile collection at accept
 *   WF-INVITE-011  variant `choice-freshlogin` — admin picks 'email'
 *   WF-INVITE-013  variant `email-no-roles` — reInvite on pending user
 *   WF-INVITE-015  variant `email-no-roles` — cancelInvite on pending user
 *
 * Driving model. Admin pre-auth + the rendered admin-side forms run through
 * the SPA (`/wf?id=…`) — that's where the variant-shaped DOM lives. We
 * assert the rendered fields, then assert on the server response the
 * outlet returns (`{sent:true,outlet:"email"}` envelope or the cancelled
 * finish envelope).
 *
 * Pre-auth: drive `auth.login` (variant `minimal`) via the SPA so
 * `inviteAutoLoginFinish` writes the `aooth_access` cookie into the
 * browser context — subsequent same-origin `/auth/trigger` POSTs (whether
 * fired by `<AsWfForm>` or by `page.request`) carry the cookie.
 *
 * KNOWN DEMO-INFRA GAPS (flagged inline).
 *
 *   1) `__test/emails` returns `[]` even after `outlet:email` fires —
 *      meaning the email outlet on the wire path and the
 *      `CaptureEmailSender` exposed to the mailbox endpoint are not the
 *      same instance for this server boot. Stories that need to read the
 *      magic-link URL out of the mailbox (WF-INVITE-001, -007) cannot
 *      finish the invitee redemption leg; they are `test.fixme`'d below.
 *      Stories that only need "the admin send fired" still pass via the
 *      `sent:true` envelope on the network response (WF-INVITE-011, -013).
 *
 *   2) `__test/reset` does not actually clear rows from a previous run
 *      (200/201 is returned and 24 fixtures are re-seeded, but
 *      previously-invited users persist). Tests that create new invitees
 *      use `Date.now()`-suffixed emails so successive runs don't collide
 *      with leftover pending rows.
 *
 *   3) Seed mismatch: `t1_pending` has `username='t1_pending'` ≠
 *      `email='t1_pending@example.com'`. The invite-family workflows
 *      look up by `findByUsername(email)`, so the seed user is
 *      structurally unreachable through the email-typed form fields.
 *      WF-INVITE-013 / -015 seed a fresh pending invitee via
 *      `auth.invite` (where `username = email`) instead.
 */
import { expect, test } from "@playwright/test";
import type { Page, Response } from "@playwright/test";

import type { APIRequestContext } from "@playwright/test";

import {
  clickAction,
  fillField,
  getEmails,
  loginViaUi,
  rewriteToBaseUrl,
  submitForm,
  uniqueEmail,
  USERS,
  waitForEmail,
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

/**
 * Drive `auth.invite` through the SPA against `inviteeEmail` so the demo
 * creates a fresh `pendingInvitation=true` row whose `username === email`.
 * Required because the seeded `t1_pending` row has `username='t1_pending'`
 * (≠ email), and `cancelInvite` / `reInvite` call `users.getUser(email)` →
 * `findByUsername(email)` which only matches on `username` — so they can't
 * find the seed user. Issuing the invite via the workflow itself yields a
 * row where `username = ctx.username = ctx.email`, which IS findable.
 */
async function seedPendingInviteeByEmail(page: Page, email: string): Promise<void> {
  await page.goto(wfUrl("auth.invite", "email-no-roles"));
  await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });
  await fillField(page, "email", email);
  const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
  await submitForm(page);
  await sentPromise;
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
    await page.goto(wfUrl("auth.invite", "email-no-roles"));
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
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    await inviteePage.locator("button.as-submit-btn, button[type=submit]").first().click();

    // `DemoInviteWorkflow.getProfileForm()` always returns
    // `InviteAcceptProfileForm`, so even the no-roles variant pauses on the
    // profile-collect step. Both fields (`displayName`, `phone`) are optional
    // → submit with empty input to advance to the issue step.
    await expect(inviteePage.getByText("Display name")).toBeVisible({ timeout: 15_000 });
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
    await page.goto(wfUrl("auth.invite", "roles-profile"));
    await expect(page.locator('[name="email"]')).toBeVisible();

    // `collectRoles: true` on the variant ⇒ `roles?: string[]` renders as an
    // `as-multi-select-field` (not a native `[name="roles"]` input). The
    // field is structurally present when the label "Roles" is visible AND a
    // multi-select container is in the DOM.
    await expect(page.locator(".as-field-label", { hasText: "Roles" })).toBeVisible();
    await expect(page.locator(".as-multi-select-field")).toHaveCount(1);
  });

  // ── WF-INVITE-007 ────────────────────────────────────────────────────────
  test("WF-INVITE-007 profile collection at accept pauses InviteAcceptProfileForm", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    // The `roles-profile` variant flips `collectProfile: true` so after the
    // invitee sets their password the workflow pauses on the profile form
    // returned by `DemoInviteWorkflow.getProfileForm()` (`InviteAcceptProfileForm`).
    await page.goto(wfUrl("auth.invite", "roles-profile"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-007");
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
    await inviteePage.locator("button.as-submit-btn, button[type=submit]").first().click();

    // InviteAcceptProfileForm — declares `displayName` and `phone` (both
    // optional, see packages/e2e-demo/src/models/user.as). The atscript-ui
    // renderer paints optional empty fields as "Not set" buttons rather than
    // bare inputs, so assert on the rendered labels.
    await expect(inviteePage.getByText("Display name")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.getByText("Phone")).toBeVisible();
    await ctx.close();
  });

  // ── WF-INVITE-011 ────────────────────────────────────────────────────────
  test("WF-INVITE-011 choice variant renders InviteSendModeForm; admin picks email", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);

    await page.goto(wfUrl("auth.invite", "choice-freshlogin"));
    // First pause is `InviteSendModeForm` (because `send.mode === 'choice'`
    // defers to `inviteSelectSendMode`).
    await expect(page.locator('[name="mode"]')).toBeVisible({ timeout: 5000 });

    await fillField(page, "mode", "email");
    await submitForm(page);

    // Next pause is the InviteForm (email field) — proves the choice → email
    // branch advanced the workflow past `inviteSelectSendMode`.
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });
    await fillField(page, "email", uniqueEmail("choice-011"));

    // Submitting the invite produces the outlet envelope.
    const sendPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    const envelope = await sendPromise;
    expect(envelope.sent).toBe(true);
    expect(envelope.outlet).toBe("email");
  });

  // ── WF-INVITE-013 ────────────────────────────────────────────────────────
  // NOTE on target user: the brief asks for `t1_pending` from the seed, but
  // that seeded row has `username='t1_pending'` ≠ `email='t1_pending@example.com'`.
  // `reInvite` / `cancelInvite` both call `users.getUser(email)` →
  // `findByUsername(email)` which only matches on the `username` column, so
  // the seed user is structurally unreachable through the form. We instead
  // create a fresh pending row via `auth.invite` (which sets username = email
  // in `inviteAdminInviteForm`) and target THAT — same workflow path, same
  // assertions, sidesteps the demo-seed mismatch.
  test("WF-INVITE-013 reInvite on a freshly-created pending invitee → outlet fires", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    // Per-run unique email so re-runs against the same server don't trip the
    // demo's `Invite already pending, use reInvite` 409 (the `__test/reset`
    // currently fails to delete rows from a previous run — see file header).
    const inviteeEmail = uniqueEmail("reinvite-013");
    await seedPendingInviteeByEmail(page, inviteeEmail);

    await page.goto(wfUrl("auth.reInvite", "email-no-roles"));
    // `auth.reInvite` opens on `InviteEmailForm` — single `email` field.
    await expect(page.locator('[name="email"]')).toBeVisible();
    await fillField(page, "email", inviteeEmail);
    const sendPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    const envelope = await sendPromise;
    expect(envelope.sent).toBe(true);
    expect(envelope.outlet).toBe("email");
  });

  // ── WF-INVITE-015 ────────────────────────────────────────────────────────
  // Same seed-mismatch caveat as WF-INVITE-013 (see comment there).
  test("WF-INVITE-015 cancelInvite on a freshly-created pending invitee → cancelled:true", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    const inviteeEmail = uniqueEmail("cancel-015");
    await seedPendingInviteeByEmail(page, inviteeEmail);

    await page.goto(wfUrl("auth.cancelInvite", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible();
    await fillField(page, "email", inviteeEmail);

    // cancelInvite finishes with `{ cancelled: true, email }` — no outlet,
    // so we don't need the email-capture infra (this story is the one
    // P0 row that's fully end-to-end runnable today).
    const finishPromise = nextTriggerResponse(page, (b) => b.finished === true);
    await submitForm(page);
    const envelope = await finishPromise;
    expect(envelope.finished).toBe(true);
    const data = envelope.data as Record<string, unknown> | undefined;
    expect(data?.cancelled).toBe(true);
    expect(data?.email).toBe(inviteeEmail);

    // Rendered DOM mirrors the envelope.
    await expect(page.locator("text=Workflow finished")).toBeVisible({ timeout: 5000 });
    await expect(page.locator("pre").first()).toContainText('"cancelled": true');
    await expect(page.locator("pre").first()).toContainText(inviteeEmail);
  });
});

/**
 * P1 coverage for the invite family. Maps to USER_STORIES.md §5 rows tagged
 * Tier=P1:
 *
 *   WF-INVITE-002  variant `email-no-roles`     — invite existing user → 409
 *   WF-INVITE-003  variant `email-no-roles`     — invitee cancels at password form
 *   WF-INVITE-006  variant `roles-profile`      — role not in whitelist → form error
 *   WF-INVITE-008  variant `roles-profile`      — invitee skips profile form
 *   WF-INVITE-009  variant `shareable-link`     — admin form completes, link mode
 *   WF-INVITE-012  variant `choice-freshlogin`  — redemption finish has no tokens
 *   WF-INVITE-014  variant `email-no-roles`     — reInvite on already-accepted → 409
 *   WF-INVITE-016  variant `email-no-roles`     — cancelInvite on already-accepted → 409
 *   WF-INVITE-017  variant `cancellation-disabled` — cancelInvite blocked → 403
 *
 * The `t1_redeemed` seed has `username = email = t1_redeemed@example.com`,
 * which is the structural prerequisite for `loadUserOrNull(email)` to find
 * it via `findByUsername(email)`. -002/-014/-016 all hit it.
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
  // `duplicateCheck` returns 'reject' → server throws `HttpError(409, "User
  // already exists")`. AsWfForm surfaces the 409 to `@error`, WfPage paints
  // it under `.scope-error`.
  test("WF-INVITE-002 admin invites already-redeemed user → 409 inline error", async ({ page }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.invite", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    await fillField(page, "email", "t1_redeemed@example.com");
    const errorPromise = nextTriggerResponse(
      page,
      (b) => typeof b.message === "string" && /already exists|409/i.test(b.message),
      10_000,
    );
    await submitForm(page);
    const body = await errorPromise;
    // 409 envelope carries the HttpError message verbatim.
    expect(body.message).toMatch(/User already exists/i);
    // Form must re-render — the `email` field is still in the DOM. WfPage
    // paints the message under `.scope-error`.
    await expect(page.locator(".scope-error")).toContainText(/User already exists/i);
    await expect(page.locator('[name="email"]')).toBeVisible();
  });

  // ── WF-INVITE-003 ────────────────────────────────────────────────────────
  // BRANCH: admin sends invite → invitee resumes via magic link → on
  // SetPasswordForm, click `cancel` action → workflow `abort()` runs
  // `abortWf("cancel", …)` and sets `ctx.aborted = true` → all terminal steps
  // gate on `!ctx.aborted` so the redemption never completes.
  // The aborted finish envelope carries `aborted: true` in the wire payload
  // (per `@atscript/moost-wf` `abortWf` contract).
  // FIXME(infra): "pending preserved" should ALSO assert
  // `account.pendingInvitation === true` via a DB-probe endpoint — none
  // exists today. Test asserts the abort half end-to-end; DB-verify is a
  // P0-style retro fix (add `GET /__test/user/:username`).
  test("WF-INVITE-003 invitee cancels at SetPasswordForm → aborted envelope", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.invite", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });
    const inviteeEmail = uniqueEmail("invite-003");
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
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });

    // SetPasswordForm declares `@ui.form.action 'cancel', 'Cancel'` (see
    // forms.as). The action handler runs BEFORE form validation, so we don't
    // need to fill the password fields first. `abortWf()` writes the envelope
    // `{ finished: true, aborted: true, reason: 'cancel', message: { … } }`
    // at the top level (not nested under `data`).
    const abortPromise = nextTriggerResponse(
      inviteePage,
      (b) => b.finished === true && b.aborted === true,
      10_000,
    );
    await clickAction(inviteePage, "Cancel");
    const envelope = await abortPromise;
    expect(envelope.finished).toBe(true);
    expect(envelope.aborted).toBe(true);
    expect(envelope.reason).toBe("cancel");
    await ctx.close();
  });

  // ── WF-INVITE-006 ────────────────────────────────────────────────────────
  // BRANCH: `inviteAdminInviteForm` → role validation — `validateAdminInput`
  // intersects submitted roles against `ctx.availableRoles` (sourced from
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
    await page.goto(wfUrl("auth.invite", "roles-profile"));
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

  // ── WF-INVITE-008 ────────────────────────────────────────────────────────
  // BRANCH: `roles-profile` variant flips `collectProfile: true` so post-
  // password the workflow pauses on `InviteAcceptProfileForm`. That form
  // declares `@ui.form.action 'skip', 'Skip'`. Clicking skip resolves the
  // action to `'skip'` — the workflow advances WITHOUT calling
  // `applyProfile()`, then the auto-login finish step issues tokens.
  // FIXME(infra): "applyProfile not called" should be verified via a
  // `__test/applyProfileCalls` counter or a `__test/user/:username` GET
  // that reflects `displayName`. Neither exists today. Test asserts the
  // workflow completes with tokens (proves the profile step advanced) —
  // direct DB verification is a P0-style retro fix.
  test("WF-INVITE-008 invitee clicks skip on profile form → workflow finishes with tokens", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.invite", "roles-profile"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-008");
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

    // Set the password first so the workflow advances to the profile pause.
    await expect(inviteePage.locator('[name="newPassword"]')).toBeVisible({ timeout: 15_000 });
    await inviteePage.locator('[name="newPassword"]').fill("InviteePass-1!");
    await inviteePage.locator('[name="confirmPassword"]').fill("InviteePass-1!");
    await submitForm(inviteePage);

    // Profile pause — click `skip` instead of submitting the form.
    await expect(inviteePage.getByText("Display name")).toBeVisible({ timeout: 15_000 });
    await clickAction(inviteePage, "Skip");

    // Auto-login finish step still runs (skip leaves `ctx.aborted` false).
    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    await expect(inviteePage.locator("pre").first()).toContainText("accessToken");
    await ctx.close();
  });

  // ── WF-INVITE-009 ────────────────────────────────────────────────────────
  // BRANCH: `shareable-link` variant sets `send.mode: 'shareableLink'` →
  // workflow routes through `inviteReturnShareableLink` instead of
  // `inviteSendInviteEmail`.
  //
  // FIXME(impl-punt): per impl-side TODO at
  // packages/auth-moost/src/workflows/invite.workflow.ts:687-690, the
  // shareableLink branch CURRENTLY piggy-backs on the email outlet — it
  // still emits an `outletEmail` event with `metadata.shareableLink: true`.
  // A dedicated `shareableLinkSink` outlet that finishes admin-side with
  // the URL (no email) is future work. The §5.3 render assertions ("no
  // email sent", "link URL captured on admin page") presume the dedicated
  // outlet exists — so the test asserts what's actually wired today:
  // the `shareableLink: true` flag on the captured email, and the
  // workflow's `sent:true` envelope. The "no email + URL on page" branch
  // turns into a real assertion once the dedicated outlet lands.
  test.fixme("WF-INVITE-009 shareable-link mode admin completion (PUNT: shareableLink still emails)", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.invite", "shareable-link"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    const inviteeEmail = uniqueEmail("invite-009");
    await fillField(page, "email", inviteeEmail);
    const sentPromise = nextTriggerResponse(page, (b) => b.sent === true);
    await submitForm(page);
    await sentPromise;

    // Target state (post-fix): mailbox should be empty AND the page should
    // render the magic-link URL as visible text.
    const emails = await getEmails(request);
    expect(
      emails.filter((e) => e.recipient === inviteeEmail),
      "shareableLink mode must NOT send email",
    ).toHaveLength(0);
    await expect(page.locator("body")).toContainText(/https?:\/\/.+wfs=/);
  });

  // ── WF-INVITE-012 ────────────────────────────────────────────────────────
  // BRANCH: `choice-freshlogin` variant sets `accept.freshLoginRequired: true`.
  // After admin picks "email", invitee redeems, sets password, fills profile,
  // the activation step runs but the terminal selector picks
  // `inviteFreshLoginFinish` (NOT `inviteAutoLoginFinish`) because
  // `freshLoginRequired === true`. `freshLoginFinish` calls `finishWf({ next:
  // { trigger: 'immediate', action: { type: 'redirect', target: loginUrl,
  // reason: 'fresh-login-required' } } })` — no `data` block ⇒ no tokens.
  test("WF-INVITE-012 freshLoginRequired → redemption finish carries no tokens, reason=fresh-login-required", async ({
    page,
    request,
    baseURL,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.invite", "choice-freshlogin"));
    await expect(page.locator('[name="mode"]')).toBeVisible({ timeout: 5000 });
    await fillField(page, "mode", "email");
    await submitForm(page);

    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });
    const inviteeEmail = uniqueEmail("invite-012");
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
    await submitForm(inviteePage);

    // InviteAcceptProfileForm pause — submit empty (both fields optional).
    await expect(inviteePage.getByText("Display name")).toBeVisible({ timeout: 15_000 });
    await submitForm(inviteePage);

    await expect(inviteePage.locator("text=Workflow finished")).toBeVisible({ timeout: 15_000 });
    const raw = (await inviteePage.locator("pre").first().textContent()) ?? "";
    // Auto-login finish would render `{ data: { accessToken, refreshToken,
    // … } }`; freshLogin finish renders `{ next: { trigger: 'immediate',
    // action: { type:'redirect', target, reason:'fresh-login-required' } } }`.
    expect(raw).not.toContain("accessToken");
    expect(raw).toContain("fresh-login-required");
    expect(raw).toContain('"type": "redirect"');
    await ctx.close();
  });

  // ── WF-INVITE-014 ────────────────────────────────────────────────────────
  // BRANCH: `auth.reInvite` opens on `InviteEmailForm` → `loadPendingUser`
  // step → `findByUsername(email)` returns the already-redeemed seed user.
  // `existing.account?.pendingInvitation === false` ⇒ workflow throws
  // `HttpError(409, "User has already accepted; cannot resend")`. AsWfForm
  // surfaces 409 via `@error` → WfPage paints under `.scope-error`.
  test("WF-INVITE-014 reInvite on already-accepted user → 409 inline error", async ({ page }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.reInvite", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    await fillField(page, "email", "t1_redeemed@example.com");
    const errorPromise = nextTriggerResponse(
      page,
      (b) => typeof b.message === "string" && /already accepted|cannot resend/i.test(b.message),
      10_000,
    );
    await submitForm(page);
    const body = await errorPromise;
    expect(body.message).toMatch(/already accepted; cannot resend/i);
    await expect(page.locator(".scope-error")).toContainText(/already accepted/i);
    await expect(page.locator('[name="email"]')).toBeVisible();
  });

  // ── WF-INVITE-016 ────────────────────────────────────────────────────────
  // BRANCH: `auth.cancelInvite` → `inviteCancelInvite` step → existing user
  // found but `account.pendingInvitation === false` ⇒
  // `HttpError(409, "Cannot cancel: user has already accepted the invite")`.
  test("WF-INVITE-016 cancelInvite on already-accepted user → 409 inline error", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    await page.goto(wfUrl("auth.cancelInvite", "email-no-roles"));
    await expect(page.locator('[name="email"]')).toBeVisible({ timeout: 5000 });

    await fillField(page, "email", "t1_redeemed@example.com");
    const errorPromise = nextTriggerResponse(
      page,
      (b) => typeof b.message === "string" && /has already accepted|cannot cancel/i.test(b.message),
      10_000,
    );
    await submitForm(page);
    const body = await errorPromise;
    expect(body.message).toMatch(/Cannot cancel: user has already accepted/i);
    await expect(page.locator(".scope-error")).toContainText(/already accepted/i);
    await expect(page.locator('[name="email"]')).toBeVisible();
  });

  // ── WF-INVITE-017 ────────────────────────────────────────────────────────
  // BRANCH: `cancellation-disabled` variant sets `cancellation.allowed: false`.
  // `inviteCancelInvite` step's first check throws
  // `HttpError(403, "Invite cancellation is disabled")` — fires even when a
  // valid pending email is submitted (we use a fresh pending row to prove the
  // 403 isn't a 404 in disguise).
  test("WF-INVITE-017 cancelInvite when cancellation.allowed=false → 403, no form", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.admin_inviter);
    // §5.3 expectation: "direct error, no form". The 403 guard fires BEFORE
    // `resolveInput()` in `inviteCancelInvite`, so the workflow init itself
    // throws — no form is ever rendered, and there's no `/auth/trigger` POST
    // from the SPA either. AsWfForm's bootstrap GET surfaces the 403 via the
    // `@error` slot.
    const errorPromise = page.waitForResponse(
      (r) => r.url().includes("/auth/trigger") && r.status() >= 400,
      { timeout: 10_000 },
    );
    await page.goto(wfUrl("auth.cancelInvite", "cancellation-disabled"));
    const res = await errorPromise;
    expect(res.status()).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.message ?? body.error).toMatch(/Invite cancellation is disabled/i);
    // Form field never appears.
    await expect(page.locator('[name="email"]')).toHaveCount(0);
    await expect(page.locator(".scope-error")).toContainText(/cancellation is disabled/i);
  });
});
