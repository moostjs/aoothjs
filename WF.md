# WF — `@aoothjs/auth-moost` workflows: redesign

This file is the master tracker for the auth-moost workflow redesign. It supersedes ISSUE-1 and ISSUE-16 in `ISSUES.md`. Per-workflow shape is documented in sibling files:

- [WF_LOGIN.md](WF_LOGIN.md) — login workflow goal + step catalog
- [WF_RECOVERY.md](WF_RECOVERY.md) — recovery / forgot-password workflow (TBD)
- [WF_INVITE.md](WF_INVITE.md) — invite / accept-invite workflow (TBD)

---

## Goal

Replace the current minimal workflows (3 steps each, anti-DI, opaque setup function) with comprehensive, opt-in-feature flows that:

1. **Use proper Moost DI** — dependencies in the constructor, not `cc.instantiate(X)` scattered through step bodies.
2. **Cover every realistic case** — channel enrollment, alt actions, password rotation, MFA selection, device trust, terms acceptance, tenant pick, etc. Most steps default OFF; turning them on is a one-line config change.
3. **Options classes via DI with reasonable defaults** — each workflow ships an `XWorkflowOptions` `@Injectable()` class with sensible defaults; consumers replace the provider entry to flip features.
4. **Options auto-injected into the workflow context** — first implicit step copies `this.opts` into `ctx.opts` so step `condition: (ctx) => ctx.opts.X && ctx.somethingTriggered` reads naturally.

---

## Common refactor (applies to every workflow class)

### Before

```ts
@Injectable("FOR_EVENT")
@Controller()
@Public()
export class LoginWorkflow {
  // No constructor; deps pulled inside steps via cc.instantiate(X)
  @Step("credentials")
  async credentials(...) {
    const cc = useControllerContext()
    const users = await cc.instantiate(UserService)
    const auth  = await cc.instantiate(AuthCredential)
    // ...
  }
}

// Setup magic that mutates a shared MoostAuthWorkflowConfig:
setupAuthWorkflows(app, { emailSender, buildMagicLinkUrl, prepareUser, ... })
```

### After

```ts
// 1. Options are a DI class with reasonable defaults.
@Injectable()
export class LoginWorkflowOptions {
  forgotPasswordAction = true
  signupAction         = false
  magicLinkAction      = false
  ssoActions: SsoProvider[] = []
  embedRecovery        = false
  recoveryUrl          = "/recover"          // where the forgotPassword alt-action navigates
  signupUrl            = "/signup"
  ensureEmail          = false
  ensurePhone          = false
  passwordExpiryGuard  = true
  passwordInitialGuard = true
  termsAcceptVersion?: string
  notifyNewDevice      = false
  redirect: 'referer' | 'home' | ((ctx: LoginWfCtx) => string) = 'referer'
  /* ... full list in WF_LOGIN.md ... */
  constructor(opts: Partial<LoginWorkflowOptions> = {}) {
    Object.assign(this, opts)
  }
}

// 2. Workflow class uses constructor DI for deps + options.
@Injectable("FOR_EVENT")
@Controller()
@Public()
export class LoginWorkflow {
  constructor(
    private opts: LoginWorkflowOptions,
    private users: UserService,
    private auth: AuthCredential,
    private authConfig: MoostAuthConfig,
    private mailer: EmailSender,
  ) {}

  @Step('init')
  init(@WorkflowParam('context') ctx: LoginWfCtx) {
    ctx.opts = this.opts                     // expose to all condition: callbacks
  }

  @Step('credentials')
  async credentials(...) {
    // Uses this.users, this.auth — no cc.instantiate() calls
  }
  /* ... rest of steps ... */
}

// 3. Consumer wiring (no setupAuthWorkflows; explicit DI):
moost.setProvideRegistry(createProvideRegistry(
  [LoginWorkflowOptions,    () => new LoginWorkflowOptions({ ensureEmail: true })],
  [RecoveryWorkflowOptions, () => new RecoveryWorkflowOptions({ ... })],
  [InviteWorkflowOptions,   () => new InviteWorkflowOptions({ ... })],
  [EmailSender,             () => myEmailSender],
))
moost.registerControllers(LoginWorkflow, RecoveryWorkflow, InviteWorkflow)
```

### Key principles

- **No `setupAuthWorkflows` orchestrator.** Same call as ISSUE-15 / ISSUE-9 #9 — wiring is visible to the consumer, not hidden behind a setup function.
- **No `MoostAuthWorkflowConfig` god-object.** Per-workflow options classes only. The current shared bag (which gets uninitialized then mutated by `setupAuthWorkflows`) is deleted.
- **Implicit `init` step on every workflow.** Convention: every workflow's first step writes `this.opts` into `ctx.opts` so step conditions can reference feature flags without an extra DI call.
- **Subclass-friendly.** Any consumer can `class MyLoginWorkflow extends LoginWorkflow { override async credentials(...) {...} }` and `setReplaceRegistry([LoginWorkflow, MyLoginWorkflow])`. Per-step override is the customization seam.
- **Hooks vs subclass.** Stateless predicates / data shapes (e.g. `redirect`, `emailToUserId`, `prepareUser`) ride on the options class as callback fields. Full step rewrites use subclass override.

### Removed surfaces

- `setupAuthWorkflows()` — deleted
- `MoostAuthWorkflowConfig` — deleted (per-workflow options replace it)
- `prepareUser` / `emailToUserId` hooks (currently on `MoostAuthWorkflowConfig`) — moved to the relevant per-workflow options class (`InviteWorkflowOptions.prepareUser`, `RecoveryWorkflowOptions.emailToUserId`)
- `cc.instantiate(X)` calls inside step bodies — replaced by constructor DI

### Kept surfaces

- The bundled atscript form models (`LoginCredentialsForm`, `MfaCodeForm`, `EmailIdentifierForm`, `SetPasswordForm`, etc.) — consumers can still subclass / replace them
- `wf-helpers` (`httpInputRequired`, `validateFormInput`, `buildFinishedCookies`, `buildLoginResponse`) — these are pure, no DI, fine as exports
- `createAuthEmailOutlet` — same, pure helper

---

## Alt actions — first-class flow control

Forms can carry alternate-action buttons (e.g. "Forgot password?", "Resend code"). When the user clicks one, moost-wf surfaces it via an `@AltAction()` param resolver. The current step inspects it and short-circuits; the workflow then routes to the alternate path.

Convention going forward:

- Each form-bearing step accepts `@AltAction() alt?: string`.
- If `alt` is set and matches a known alt-action key for that step, the step resolves to a redirect/navigation outlet (`useWfFinished().set({ type: 'redirect', value: this.opts.recoveryUrl })`) rather than processing the input.
- Each option flag that enables an alt-action also documents the URL the consumer wants to navigate to (e.g. `opts.recoveryUrl`, `opts.signupUrl`).

**Decision: alt-action navigates to a sibling workflow URL, not embedded inline** (per design call 2026-05-15). Inline embedding is hidden behind `opts.embedRecovery` for advanced consumers.

Per-form alt-action catalog lives in the per-workflow file (e.g. WF_LOGIN.md).

---

## Email outlets

`createAuthEmailOutlet(...)` stays as a helper — it builds the email payload + the magic-link URL. Workflows inject an `EmailSender` via DI and call the outlet helper from steps. Same pattern; no setup magic.

---

## Tasks (high-level)

1. **Architecture switch** — refactor `LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow` constructors + delete `MoostAuthWorkflowConfig` + `setupAuthWorkflows`.
2. **Options classes** — define `LoginWorkflowOptions`, `RecoveryWorkflowOptions`, `InviteWorkflowOptions` with full defaults per the per-workflow specs.
3. **Step expansion** — implement the full step catalogs from WF_LOGIN.md / WF_RECOVERY.md / WF_INVITE.md, all gated by opts.
4. **Alt actions** — wire `@AltAction()` resolvers on every form-bearing step.
5. **Tests** — per-workflow scenario coverage: each opt OFF (default flow), each opt ON (feature path), each alt action.
6. **e2e demo** — flip from `setupAuthWorkflows(...)` to the new explicit registration.

---

## Reference

The flow shapes draw heavily from `../rvmode/packages/app-portal/src/auth/interface/workflows/auth.workflow.ts` — the production-grade reference for what a "real" auth workflow looks like (channel enrollment loops, parametric pincode steps, alt actions, masked recipient display, etc.).
