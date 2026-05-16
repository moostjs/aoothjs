# TASKS — implementation plan (architect/orchestrator mode)

This file is the master implementation plan for executing all decisions captured in [ISSUES.md](ISSUES.md), [WF.md](WF.md), [WF_LOGIN.md](WF_LOGIN.md), [WF_RECOVERY.md](WF_RECOVERY.md), and [WF_INVITE.md](WF_INVITE.md).

**Persistence purpose:** if context is lost, re-read THIS file plus the source-of-truth design docs above; status checkboxes below show exactly where to resume.

---

## Role

I am the **architect + orchestrator**. I do not write code directly. I:

1. Brief a subagent (per the protocol below) to make the change.
2. Brief a second subagent to run the `simplify` skill on the diff.
3. Personally **validate** the result against the documented decision in the source-of-truth file (ISSUES.md / WF\*.md).
4. If deviations found:
   - **Justified deviation** → document it in the source-of-truth file with a `**Deviation:**` block citing what was changed and why.
   - **Unjustified deviation** → spin a new subagent to bring the implementation back in line.
5. Commit when the issue is fully resolved (fix + simplify + validation + any deviation handling).
6. Move to the next item.

**Never skip a phase. Never batch commits across multiple issues. One issue → one (or two) commit(s).**

---

## Per-task subagent protocol

### Step 1 — Implementation subagent

Spawn `general-purpose` subagent with a prompt containing:

- **Self-contained context.** The subagent has not seen this conversation. Brief it like a smart colleague who walked in cold.
- **The exact source-of-truth section.** Quote the relevant ISSUES.md `### ISSUE-N` block (or the relevant WF\*.md section) verbatim or by stable file:line link.
- **The acceptance criteria** — what files must change, what behavior must hold, what the diff should look like. (Test-writing is its own dedicated Step 3 — do NOT push it onto Step 1's prompt; the implementation subagent should focus on production code, not test coverage.)
- **The recommended skills** — name skills the subagent should invoke. Standard list: `moostjs`, `wooksjs`, `atscript-db`, `atscript-ui-forms` (when forms involved). Always remind it to consult them BEFORE writing code that touches those subsystems.
- **The "must verify" list** — typecheck (`pnpm run check` in the touched packages); existing tests must still pass (`pnpm run test`); `pnpm run ready` only when the change is large enough to warrant it.
- **Reminder to NOT add migration/deprecation/backwards-compat shims** — pre-release, no users yet, hard cuts only.

### Step 2 — Simplify subagent

Spawn `general-purpose` subagent with the `simplify` skill.

- Pass it the diff from Step 1.
- Let it run all three review agents (reuse / quality / efficiency) and apply non-controversial cleanups.

### Step 3 — Tests subagent (MANDATORY — never skip)

Spawn `general-purpose` subagent dedicated to **writing or updating unit AND e2e tests** so the existing and the new behavior are both covered completely. Brief it with:

- The diff from Step 1 + 2 so it sees what production code changed.
- The source-of-truth decision so it knows the **intent** behind the change (Rule 9 — tests verify intent, not just behavior; a test that can't fail when business logic changes is wrong).
- The list of test files most likely to need updates: `*.spec.ts` in the touched package(s) for unit coverage, `packages/e2e-demo/test/*.spec.ts` for end-to-end coverage.
- An explicit checklist:
  1. **Existing tests**: any test that broke with the change must be repaired (and the test must still encode its original intent — not weakened to "make it pass").
  2. **New tests**: every actionable item in the source-of-truth decision must have at least one test that proves the rule. Negative tests too — when the design says "throws when X" or "rejects when Y", there's a test asserting that.
  3. **e2e coverage**: any HTTP/workflow surface that changed gets at least one e2e scenario.
  4. **Coverage holes**: if the implementation introduced a new code path that has no test, write one.
- The verification command: `pnpm run test -r` (or `pnpm run ready` if the change is large) must pass GREEN with the new tests included before declaring this step done.

If the tests subagent uncovers a real bug in Step 1's implementation, raise it back to me — I decide whether to re-spawn Step 1 or accept the test as red and document the bug.

### Step 4 — Validation (architect, no subagent)

I personally:

- Read the full diff (`git diff HEAD`) — both production code AND tests.
- Read the source-of-truth section.
- Walk through every actionable item in the decision and confirm it lands in the diff.
- Walk through the tests checklist (Step 3 items 1–4) and confirm each is covered.
- Run quick verification commands (`vp check`, `vp test` in touched packages).
- Decide: "matches", "justified deviation" (record), or "unjustified deviation" (re-spawn the appropriate step).

**Do not move to commit if any test was skipped, weakened, or marked `it.skip` without an explicit recorded justification.** Rule 12 — fail loud.

### Step 5 — Commit

Single-line commit message, no co-author trailers (per saved feedback memory). Format:

```
<type>(<scope>): <ISSUE-N or WF*-N> short summary
```

Examples:

- `chore(arbac-moost): ISSUE-3 drop CurrentArbacScopes alias`
- `feat(auth-moost): WF_LOGIN device-trust check + cookie write steps`

When the change is large, prefer **two commits** (production code, then tests) over one mega-commit — easier to review, easier to bisect. Both still belong to the same task (mark `[x]` only after both land).

---

## Standing constraints (apply to every task)

- **Pre-release.** No migration helpers, no `@deprecated` shims, no compat re-exports. Hard cuts only.
- **One-line commit messages.** No co-author trailers (per saved memory).
- **Prefer editing existing files.** No new files unless the design doc explicitly mandates one.
- **No emojis** in code or docs.
- **Testing discipline.** Each fix gets at least one test that proves the rule, not just the behavior. If the design says "throws when X", there's a test asserting that throw.
- **Rule 3 / surgical changes.** Touch only what the issue requires. No drive-by cleanups in unrelated files.

## Context-window management

I cannot programmatically read my own token usage; there is no tool that returns current context size, and `/compact` is a built-in CLI command I cannot invoke as a tool. So this is a **proxy-based discipline**, not auto-detection:

- **Natural compact checkpoints.** After every commit (Step 5 of the per-task protocol), pause and ask the user: _"Just committed `<scope>`. Conversation has been running since `<rough marker>` — recommend `/compact` before starting `<next item>`?"_ Let them decide.
- **Hard checkpoint.** If I have completed **3 issues since the last compact** AND the next item is structural (anything in BIG 2 or BIG 3, or any `ISSUE-N` whose decision text is longer than ~30 lines), I will stop after that commit and explicitly recommend `/compact` regardless of what the user said before. Better to over-recommend than to thrash a large structural change in a tight context.
- **Soft signals to over-weight.** If any of these fired in the last few turns, treat the context as "likely full" and recommend compact sooner:
  - I read a single file >500 lines into my own context (vs. a subagent reading it).
  - A subagent's returned summary was unusually long (>2k characters of detail).
  - I had to reload TASKS.md or any WF\*.md file because I couldn't recall its content (read-twice-in-the-same-session is a bad smell).
- **Strong preference for subagents over direct reads.** Per the protocol, all production code reading + writing happens inside subagents. Their full transcripts don't come back to my main context — only their final summary. Use this aggressively. If I'm tempted to `Read` a large file directly to "just check something", route it through `Explore` or a `general-purpose` subagent instead.
- **After compact: re-read TASKS.md first.** Then `git log --oneline -10` and `git status` to see what's already done. The Resume protocol below covers this in detail.

---

## BIG 1 — Address ISSUES.md

Order suggested in [ISSUES.md § Reading order suggestion](ISSUES.md): small/obvious first, structural last.

Within each item, the **bold action** is the heart of the change; check off when implementation + simplify + validation + commit are all done.

| #   | ISSUE                                                                                                                      | Decision                                                                                                                                                                              | Status        |
| --- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| 1   | [ISSUE-3](ISSUES.md#issue-3--arbacscopes-vs-currentarbacscopes--drop-the-alias)                                            | REMOVE `CurrentArbacScopes`                                                                                                                                                           | [x] (f9ed656) |
| 2   | [ISSUE-7](ISSUES.md#issue-7--applyarbacguardglobally--remove)                                                              | REMOVE `applyArbacGuardGlobally`                                                                                                                                                      | [x] (04cbfd7) |
| 3   | [ISSUE-10](ISSUES.md#issue-10--getarbacextractspec--getarbacprojection--should-be-internal)                                | DEMOTE to internal (folded into ISSUE-9)                                                                                                                                              | [x] (06210c9) |
| 4   | [ISSUE-11](ISSUES.md#issue-11--extractarbacuserid--roles--attrs--fold-into-atscriptarbacuserprovider-as-protected-methods) | FOLD as protected methods (folded into ISSUE-9)                                                                                                                                       | [x] (06210c9) |
| 5   | [ISSUE-9](ISSUES.md#issue-9--setuserrecordfetcher--userrecordfetcher--anti-di)                                             | REDESIGN — `AtscriptArbacUserProvider` abstract base; delete setter; delete `setupArbacFromAtscript`. Sub-tasks bundle ISSUE-10/11/15/17 + the `MoostAuthConfig` ctor change          | [x] (06210c9) |
| 6   | [ISSUE-15](ISSUES.md#issue-15--setupauthmoostapp--setup-helper--remove)                                                    | REMOVE `setupAuthMoost` (folded into ISSUE-9 #8/#9)                                                                                                                                   | [x] (06210c9) |
| 7   | [ISSUE-17](ISSUES.md#issue-17--setuparbacfromatscriptapp-type-setup-helper--remove)                                        | REMOVE `setupArbacFromAtscript` (folded into ISSUE-9 #2)                                                                                                                              | [x] (06210c9) |
| 8   | [ISSUE-4](ISSUES.md#issue-4--drop-arbacpublic-public-is-the-only-bypass-and-it-bypasses-everything)                        | DROP `@ArbacPublic`; `@Public` becomes combined; bundled middle-ground methods get `public.*` action prefix (Form B); update e2e demo roles                                           | [x] (4814f3d) |
| 9   | [ISSUE-5](ISSUES.md#issue-5--userid--user-param-resolvers--missing)                                                        | ADD `@UserId()`; rename `getCurrentUser → getAuthContext`; rename `getCurrentUserId → getUserId` (folds ISSUE-6)                                                                      | [x] (fc1c2b7) |
| 10  | [ISSUE-6](ISSUES.md#issue-6--useauth-my-recap-was-inaccurate)                                                              | RENAME `getCurrentUserId → getUserId` (bundled with ISSUE-5)                                                                                                                          | [x] (fc1c2b7) |
| 11  | [ISSUE-12](ISSUES.md#issue-12--arbacresourcename-decorator--keep)                                                          | KEEP — no action                                                                                                                                                                      | [x]           |
| 12  | [ISSUE-13](ISSUES.md#issue-13--arbacactionname-decorator--keep-but-drop-normalizeautocrudmethod)                           | DROP `normalizeAutoCrudMethod`; expand `TABLE_READ_ACTIONS` / `TABLE_WRITE_ACTIONS` to literal AsDbController method names                                                            | [x] (66b829d) |
| 13  | [ISSUE-14](ISSUES.md#issue-14--usearbac-composable-shape--keep)                                                            | KEEP — no action                                                                                                                                                                      | [x]           |
| 14  | [ISSUE-18](ISSUES.md#issue-18--as-model-annotations-aoothuserid--roles--attr--public--private)                             | KEEP `userId/roles/attr` (with new userId fallback chain; multi-shape roles support including `@db.rel.from`); REMOVE `public`/`private`                                              | [x] (d976baf) |
| 15  | [ISSUE-19](ISSUES.md#issue-19--aoothjsauth-primitives--keep-core--add-adapter-entry-points)                                | ADD `@aoothjs/auth/redis` + `@aoothjs/auth/atscript-db` subpaths with structural `RedisLike` interface (no peer dep on Redis client); ship `.as` model for atscript-db credential row | [x] (18fd50a) |
| 16  | [ISSUE-20](ISSUES.md#issue-20--aoothjsuser-primitives--keep-core--fold-user-as-into-subpath)                               | FOLD `@aoothjs/user-as` into `@aoothjs/user/atscript-db` subpath; rename class `UsersStoreAs → UsersStoreAtscriptDb`; delete the standalone package; update e2e demo imports          | [x] (4ce60a1) |
| 17  | [ISSUE-21](ISSUES.md#issue-21--tablereadwriteactionsactionprivilege-factories--rename--merge)                              | MERGE plural+singular `tableActionPrivilege`s; RENAME `*Privilege` → `allow*` family                                                                                                  | [x] (66b829d) |
| 18  | [ISSUE-22](ISSUES.md#issue-22--definerolenameallowbuild-builder--keep)                                                     | KEEP — no action                                                                                                                                                                      | [x]           |
| 19  | [ISSUE-23](ISSUES.md#issue-23--canaccess--cancrud--remove-both)                                                            | REMOVE `canAccess` + `canCrud`; rewrite e2e demo roles to use `defineRole().allow(...)` directly                                                                                      | [x] (66b829d) |
| 20  | [ISSUE-24](ISSUES.md#issue-24--missing-user-management-privilege-factory--do-not-ship)                                     | DO NOT SHIP — no action                                                                                                                                                               | [x]           |
| 21  | [ISSUE-25](ISSUES.md#issue-25--credentialstoreencapsulated-lacks-revocation-epoch--fix)                                    | FIX — port BUG-4 epoch-map + guard pattern from JWT store to encapsulated store                                                                                                       | [ ]           |
| 22  | [ISSUE-26](ISSUES.md#issue-26--as-never-cast-in-assertinscopes-tablecount-call--accept)                                    | ACCEPT — add comment near the cast                                                                                                                                                    | [x] (4642e8f) |
| 23  | [ISSUE-27](ISSUES.md#issue-27--userservicecreateuser-writes-id---fix-upstream)                                             | FIX — `UserService.createUser` must not include `id` field unless caller supplied it; remove demo-side workaround                                                                     | [x] (4d0a5d9) |
| 24  | [ISSUE-2](ISSUES.md#issue-2--defineprivilege-exported--looks-good)                                                         | KEEP — no action                                                                                                                                                                      | [x]           |
| 25  | [ISSUE-8](ISSUES.md#issue-8--arbacauthorize-wrapper--keep)                                                                 | KEEP — no action                                                                                                                                                                      | [x]           |

**Suggested execution order** (dependency-aware; small first, larger structural last):

1. Standalone deletes (independent, small): **ISSUE-3 → ISSUE-7 → ISSUE-22 (already done)** then **ISSUE-26**
2. Easy renames / merges: **ISSUE-21 → ISSUE-23 → ISSUE-13** (these touch privilege factories together; do them in one branch flow)
3. `@aoothjs/user` upstream fix: **ISSUE-27**
4. Structural redesign cluster (do in one go, single commit per sub-step): **ISSUE-9 (which sweeps in 10/11/15/17)**, plus simultaneously the `MoostAuthConfig` ctor change
5. Decorator cleanup: **ISSUE-4** (touches both arbac-moost and auth-moost; e2e demo follows)
6. `@Public` follow-on: **ISSUE-5 (+ ISSUE-6 bundled)**
7. Atscript model annotations: **ISSUE-18**
8. Adapter packaging: **ISSUE-19** then **ISSUE-20**
9. Encapsulated-store epoch: **ISSUE-25**

After every full pass: run `pnpm run ready` (full quality gate) before declaring BIG 1 done.

---

## BIG 2 — WF.md common refactor

**MANDATORY checkpoint before starting BIG 2: run `/compact`.** Per user direction 2026-05-15. The transition from BIG 1 (small/medium issues) to BIG 2 (structural workflow refactor) is the natural breakpoint where prior implementation chatter no longer needs to be in context — the WF\*.md design docs are the authoritative reference from this point on.

**Source of truth:** [WF.md](WF.md).

Single-purpose: rip out the anti-DI shape from all three workflow classes + the `setupAuthWorkflows` orchestrator, replace with proper constructor DI + per-workflow options classes that get wired via `setProvideRegistry`.

| Step | Description                                                                                                                                                                                                                                                                                                                                  | Status |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 2.1  | Define `LoginWorkflowOptions`, `RecoveryWorkflowOptions`, `InviteWorkflowOptions` shells with reasonable defaults (per WF\*.md). Constructor takes `Partial<...>` and `Object.assign`s.                                                                                                                                                      | [ ]    |
| 2.2  | Refactor `LoginWorkflow` constructor — DI: opts + `UserService` + `AuthCredential` + `MoostAuthConfig` + `EmailSender` (+ optional `SmsSender` later). Drop `cc.instantiate(...)` from step bodies. Add implicit `init` step writing `this.opts → ctx.opts`. Keep step semantics IDENTICAL to today's behavior — feature expansion is BIG 3. | [ ]    |
| 2.3  | Same as 2.2 for `RecoveryWorkflow`.                                                                                                                                                                                                                                                                                                          | [ ]    |
| 2.4  | Same as 2.2 for `InviteWorkflow`.                                                                                                                                                                                                                                                                                                            | [ ]    |
| 2.5  | Move `prepareUser` hook from `MoostAuthWorkflowConfig` → `InviteWorkflowOptions.prepareUser`. Move `emailToUserId` → `RecoveryWorkflowOptions.emailToUserId`.                                                                                                                                                                                | [ ]    |
| 2.6  | DELETE `MoostAuthWorkflowConfig` entirely.                                                                                                                                                                                                                                                                                                   | [ ]    |
| 2.7  | DELETE `setupAuthWorkflows` entirely.                                                                                                                                                                                                                                                                                                        | [ ]    |
| 2.8  | Update e2e demo `app.ts` to wire workflows via `setProvideRegistry` + `registerControllers` directly (no setup function).                                                                                                                                                                                                                    | [ ]    |
| 2.9  | All existing workflow tests must still pass. No behavior change in this BIG — only DI shape.                                                                                                                                                                                                                                                 | [ ]    |

**Don't start BIG 3 until BIG 2 lands cleanly.** BIG 3 builds on top of the new DI shape.

---

## BIG 3 — Per-workflow re-implementation

For each workflow, expand the step catalog per the design doc. Drive feature flags from the options class. All new steps gated by opts so existing test scenarios (default opts) keep passing.

### BIG 3.1 — WF_LOGIN.md re-implementation

**Source of truth:** [WF_LOGIN.md](WF_LOGIN.md).

Implementation order:

| Step   | Description                                                                                                                                                                                                                                                    | Status |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 3.1.1  | Expand `LoginWorkflowOptions` to the full shape (per WF_LOGIN.md). All 25+ opts with documented defaults.                                                                                                                                                      | [ ]    |
| 3.1.2  | Define `SmsSender` interface in `@aoothjs/auth` (mirrors `EmailSender`); extend the email/SMS event union with `login.pincode`, `recovery.pincode`, `invite.pincode`, `notifyNewDevice`.                                                                       | [ ]    |
| 3.1.3  | Implement Phase 1 alternate credential paths: `magicLinkRequest`, `magicLinkSend`, `magicLinkVerified`, `passkey` (stub), `ssoCallback` (stub). Wire `magicLink` alt-action on `credentials`.                                                                  | [ ]    |
| 3.1.4  | Implement Phase 2 inline guards (already present today; verify behavior).                                                                                                                                                                                      | [ ]    |
| 3.1.5  | Implement Phase 3 enrollment loops: `ensureEmail` + `ensurePhone` (with `ask-email`/`ask-phone-number` + `set-mfa/<transport>` + `pincode-send-activate` + `pincode-confirm`).                                                                                 | [ ]    |
| 3.1.6  | Implement Phase 4 MFA: `prepare-mfa-options`, `select2fa`, `pincode-send-login`, `pincode-check-login`, `mfa-totp`, `mfa-backup-code`, `mfa-enroll-required`. Define new atscript form models: `Select2faForm`, `PincodeForm`, `AskEmailForm`, `AskPhoneForm`. | [ ]    |
| 3.1.7  | Implement device-trust: `check-trusted-device` (start of Phase 4) + `device-trust` (after MFA) + `DeviceTrustStore` interface (in-memory default; document Redis impl path). HMAC-signed cookie.                                                               | [ ]    |
| 3.1.8  | Implement Phase 5 forced password change: `prepare-password-rules` + `create-password-form`.                                                                                                                                                                   | [ ]    |
| 3.1.9  | Implement Phase 6 acceptance/onboarding: `terms-accept`, `profile-complete`, `consent-marketing`. New form models.                                                                                                                                             | [ ]    |
| 3.1.10 | Implement Phase 7 tenant/persona: `tenant-select`, `persona-select`.                                                                                                                                                                                           | [ ]    |
| 3.1.11 | Implement Phase 8 session policy: `concurrency-limit`, `risk-step-up`.                                                                                                                                                                                         | [ ]    |
| 3.1.12 | Implement Phase 9 finalize: `audit-login`, `notify-new-device`, `redirect`. Existing `issue` step stays.                                                                                                                                                       | [ ]    |
| 3.1.13 | Wire all alt actions per the catalog (every form-bearing step gets `@AltAction()` + routing).                                                                                                                                                                  | [ ]    |
| 3.1.14 | Tests: full coverage matrix per WF_LOGIN.md task #6.                                                                                                                                                                                                           | [ ]    |
| 3.1.15 | e2e demo: pick representative subset (per WF_LOGIN.md task #7).                                                                                                                                                                                                | [ ]    |

### BIG 3.2 — WF_RECOVERY.md re-implementation

**Source of truth:** [WF_RECOVERY.md](WF_RECOVERY.md).

| Step  | Description                                                                                                                                                                                                                                           | Status |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 3.2.1 | Expand `RecoveryWorkflowOptions` to the full shape.                                                                                                                                                                                                   | [ ]    |
| 3.2.2 | Define `WorkflowRateLimitStore` interface in a shared location (mentioned in WF_RECOVERY task #2 as `RecoveryRateLimitStore` — rename to shared); ship in-memory default.                                                                             | [ ]    |
| 3.2.3 | Implement step catalog: `request` (with rate-limit + URL-param pre-fill from login workflow), `selectMode`, `sendMagicLink`, `sendOtp`, `checkOtp`, `verifyFactor`, `setPassword`, `revokeSessions`, `audit`, `freshLoginFinish` / `autoLoginFinish`. | [ ]    |
| 3.2.4 | New form models: `OtpCodeForm` (with codeLength field), `RecoveryModeSelectForm`, `RecoveryFactorForm`. Reuse `EmailIdentifierForm` and `SetPasswordForm`.                                                                                            | [ ]    |
| 3.2.5 | Wire OTP via `EmailSender` / `SmsSender` (defined in BIG 3.1.2).                                                                                                                                                                                      | [ ]    |
| 3.2.6 | Wire alt actions per the catalog.                                                                                                                                                                                                                     | [ ]    |
| 3.2.7 | Tests: full coverage matrix per WF_RECOVERY.md task #8.                                                                                                                                                                                               | [ ]    |
| 3.2.8 | e2e demo: keep magicLink default + add otp-mode variant.                                                                                                                                                                                              | [ ]    |

### BIG 3.3 — WF_INVITE.md re-implementation

**Source of truth:** [WF_INVITE.md](WF_INVITE.md).

| Step   | Description                                                                                                                                                                                                                                                                                                       | Status |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 3.3.1  | Expand `InviteWorkflowOptions` to the full shape.                                                                                                                                                                                                                                                                 | [ ]    |
| 3.3.2  | Add `pendingInvitation: boolean` to `UserCredentials` shape (`@aoothjs/user`); ensure `UsersStoreMemory` and `UsersStoreAtscriptDb` (post-ISSUE-20) propagate it.                                                                                                                                                 | [ ]    |
| 3.3.3  | Implement three workflows: `auth.invite`, `auth.reInvite`, `auth.cancelInvite`, sharing the user-side accept tail via composed schemas.                                                                                                                                                                           | [ ]    |
| 3.3.4  | Implement admin-side: `assertAdminAuth`, `prepareAvailableRoles`, `selectSendMode`, `adminInviteForm`, `inferRolesStep`, `preCreateUser`, `sendInviteEmail` / `returnShareableLink`.                                                                                                                              | [ ]    |
| 3.3.5  | Implement user-side accept tail: `checkPendingInvitation` (with hard-delete-cancellation handling → 410), `idempotentRedirect`, `preparePasswordRules`, `createPasswordForm`, `collectProfile`, `applyProfile`, `unsetPendingInvitation`, `activateUser`, `confirmation`, `freshLoginFinish` / `autoLoginFinish`. | [ ]    |
| 3.3.6  | Implement `cancelInvite` (hard delete).                                                                                                                                                                                                                                                                           | [ ]    |
| 3.3.7  | Implement `loadPendingUser` (re-invite path).                                                                                                                                                                                                                                                                     | [ ]    |
| 3.3.8  | Wire `acceptProfileForm` auto-injection mechanism (consumer-supplied schema → step renders it).                                                                                                                                                                                                                   | [ ]    |
| 3.3.9  | Wire `applyProfile` escape hatch + default deep-merge fallback.                                                                                                                                                                                                                                                   | [ ]    |
| 3.3.10 | Wire alt actions per the catalog.                                                                                                                                                                                                                                                                                 | [ ]    |
| 3.3.11 | Wire shared `WorkflowRateLimitStore` (from BIG 3.2.2).                                                                                                                                                                                                                                                            | [ ]    |
| 3.3.12 | Audit events: `invite.created`, `invite.resent`, `invite.accepted`, `invite.cancelled`.                                                                                                                                                                                                                           | [ ]    |
| 3.3.13 | Tests: full coverage matrix per WF_INVITE.md task #11.                                                                                                                                                                                                                                                            | [ ]    |
| 3.3.14 | e2e demo: convert to new shape; demonstrate custom profile form + `applyProfile`.                                                                                                                                                                                                                                 | [ ]    |

---

## Out-of-scope for this plan (deferred)

The following are referenced from the design docs but NOT in scope:

- **`auth.signup`** — login's `signupAction` redirects to `signupUrl`; no `WF_SIGNUP.md` written yet. Defer until BIG 3 lands.
- **`auth.changeEmail`** — sibling of recovery for email change. Defer.
- **`auth.changePassword` workflow** — REST endpoint covers the simple case; multi-step variant is future work.
- **Tier 2 standalone workflows** (`auth.mfaEnroll`, `auth.mfaRemove`, `auth.regenerateBackupCodes`, `auth.deactivateAccount`, `auth.reactivateAccount`) — future work.

When user signals readiness, draft these as new `WF_*.md` files following the same pattern.

---

## Resume protocol (if context lost)

1. **Read this file in full.**
2. Find the lowest-numbered unchecked item.
3. Open the source-of-truth section it references.
4. Run `git log --oneline -10` to see what's already committed (commits should map to the checked items above).
5. Run `git status` and `git diff HEAD` to see any uncommitted work.
6. If there's uncommitted work matching an in-flight item: validate it (Step 3 of the protocol) and commit (Step 4) before moving on.
7. Otherwise: spawn the implementation subagent for the next unchecked item.
8. Update the status checkbox in this file as part of the same commit.

---

## Status legend

- `[ ]` — not started
- `[~]` — in progress (subagent spawned, not yet committed)
- `[!]` — blocked (with a one-line note explaining the blocker)
- `[x]` — done and committed

When marking `[x]`, append the commit short-sha in parentheses, e.g. `[x] (a1b2c3d)`.
