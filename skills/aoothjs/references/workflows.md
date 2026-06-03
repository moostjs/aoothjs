# Workflows (auth-moost)

ONE class `AuthWorkflow` with four `@Workflow` methods. Replaces the removed `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` quartet. Login/invite/recovery dispatch via `POST /auth/trigger`; change-password via its own guarded `POST /auth/change-password`.

| `@Workflow` method   | wfid                        | covers                                     |
| -------------------- | --------------------------- | ------------------------------------------ |
| `loginFlow`          | `auth/login/flow`           | login + MFA + enrollment + finalize        |
| `inviteFlow`         | `auth/invite/start`         | admin invite → anonymous magic-link accept |
| `recoveryFlow`       | `auth/recovery/flow`        | magic-link OR OTP password reset           |
| `changePasswordFlow` | `auth/change-password/flow` | authenticated self-service password change |

## Quick start — subclass + register

```ts
import {
  AuthWorkflow,
  ConsentStore,
  type AuthWfCtx,
  type AuthDeliveryPayload,
} from "@aooth/auth-moost";
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Controller, Inherit, createReplaceRegistry } from "moost";

@Inherit()
@Controller() // SINGLETON; add @Injectable("FOR_EVENT") ONLY if ctor reads composables
class MyAuth extends AuthWorkflow {
  // RE-DECLARE the 4-arg ctor (4th = ConsentStore) so TS emits design:paramtypes
  constructor(users: UserService, auth: AuthCredential, consents: ConsentStore) {
    super({ totpIssuer: "MyApp", loginUrl: "/sign-in" }, users, auth, consents);
  }
  protected override resolveMfaPolicy(_ctx: AuthWfCtx) {
    return { mode: "required" as const, availableTransports: ["email", "totp"] as const };
  }
  protected override async deliver(payload: AuthDeliveryPayload) {
    if (payload.channel === "email") await email.send(/* … */);
    else await sms.send(/* … */);
  }
}
app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, MyAuth]));
app.registerControllers(AuthController, MyAuth);
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Config split:** `AuthWorkflowOpts` is infrastructure-only (pincode timers, `loginUrl`, `totpIssuer`, device-trust cookie cfg, `forms.*`). Policy lives on `protected resolveXxx(ctx)` getters — NEVER add policy to opts.                                                                                                                                                                                                                                                                                                       |
| 2   | **Subclass decorators:** `@Inherit() @Controller()`. moost@0.6.x does NOT inherit decorators across `extends`. Add `@Injectable("FOR_EVENT")` ONLY when the ctor reads request-scoped composables.                                                                                                                                                                                                                                                                                                                                |
| 3   | **Re-declare the 4-arg ctor** `(opts, users, auth, consentStore)` — without it TS emits `design:paramtypes []` and DI fails.                                                                                                                                                                                                                                                                                                                                                                                                      |
| 4   | **Flow discrimination = ctx-slot presence, NEVER a flow name.** `AuthWfCtx` has no `flow` field. `ctx.admin`→invite-admin, `ctx.accept`→invite-accept, `ctx.postReset`→recovery, none→login.                                                                                                                                                                                                                                                                                                                                      |
| 5   | **`resolveXxx` return type is `T \| Promise<T>` — never `async` on the default.** Override with `async` in a subclass. Defaults are hardcoded policy in the resolver body.                                                                                                                                                                                                                                                                                                                                                        |
| 6   | **`resolveXxx` names are reserved for getters** — NEVER use one as a `@Step` id or `@Step` handler method name. Paired step ids are `prepare-<kebab-group>`.                                                                                                                                                                                                                                                                                                                                                                      |
| 7   | **`deliver(payload: AuthDeliveryPayload)` is the only direct-dispatch hook.** Branch on `payload.kind` + `payload.channel`. There is NO `audit()` method. The invite magic link is NOT sent via `deliver` — it goes through the email outlet (resume URL minted post-yield).                                                                                                                                                                                                                                                      |
| 8   | **`ConsentStore.getPendingConsents(subject)` is USER-SCOPED ONLY** — the arg is the stable user id (`ctx.subject`), no workflow/channel arg. Returned set must not vary by flow. OTP channel consent is separate (`recordOtpChannelConsent` + `resolveOtpDisclosure`).                                                                                                                                                                                                                                                            |
| 9   | **Error posture:** `wf.requireInput({errors, formMessage?})` = retriable (re-renders under SAME `wfs` handle, token survives) for anything the user can fix on the form; `throw new HttpError(...)` = terminal (consumes token). Throwing HttpError(4xx) for a user-fixable error → next submit hits a dead handle → 410.                                                                                                                                                                                                         |
| 10  | **`delete ctx.field`, not `ctx.field = undefined`** — the state JSON-schema-validates and rejects `undefined`. Assign `false`/`null` if a forward step reads presence.                                                                                                                                                                                                                                                                                                                                                            |
| 11  | **`@Public()` placement:** the login/invite/recovery `@Workflow` bodies are `@Public()`; reachable-anon `@Step`s are per-step `@Public()`; invite admin-phase steps omit it (ARBAC-gated on the `invite` permission). **change-password is fully gated — NO `@Public()` anywhere.**                                                                                                                                                                                                                                               |
| 12  | **wfs token rotates only at: start, finish (then 410 on reuse), wfid change.** Stable across `requireInput` retries / refresh / bookmark / multi-tab.                                                                                                                                                                                                                                                                                                                                                                             |
| 13  | **change-password is ARBAC-gated end-to-end.** The `@Workflow` body, the `POST /auth/change-password` trigger, AND all 5 steps carry `@ArbacResource("auth.change-password") @ArbacAction("self")` (method-level resource overrides the class `"auth"`). Customer enables with one grant `allow("auth.change-password","*")`; omitting it forbids the flow (the privilege IS the on/off switch — no opts flag). A bare step would fall to `resource=ClassName, action=methodName` and 403 mid-run — every step MUST be decorated. |
| 14  | **change-password identity is session-bound:** `init-change-password` sets `ctx.subject = useAuth().getUserId()` (the stable user id; `AuthWfCtx.subject`, formerly `username`) — NO target-user param. Policy on `resolveChangePasswordPolicy(ctx)`: `revokeOtherSessions` (default true) + optional `rateLimit:{minIntervalMs}`. Finish re-issues the acting token (current device stays in). wfid `CHANGE_PASSWORD_WORKFLOW`, NOT in `DEFAULT_AUTH_WORKFLOWS`.                                                                 |

## Wire contract (`/auth/trigger`)

- **Start:** body `{ wfid: "auth/login/flow", input?: { action?, formData? } }` (no token). Wfid must be in `DEFAULT_AUTH_WORKFLOWS`.
- **Resume:** body `{ wfs: "<token>", input: { action?, formData? } }`. Form values under `input.formData`; alt-actions under `input.action`.
- Response: `WfFinished` envelope (paused form / finished / aborted).

## WfTriggerProvider — state + outlets

```ts
import { WfTriggerProvider, createAuthEmailOutlet } from "@aooth/auth-moost";
import { HandleStateStrategy, MoostWf, type WfStateStrategy } from "@moostjs/event-wf";
import { AsWfStore } from "@atscript/moost-wf";

@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf, auth: AuthCredential) {
    // ctor is (wf, auth)
    super(wf, auth);
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({ emailSender, buildMagicLinkUrl, magicLinkTtlMs }),
    ];
  }
  protected override storeStrategy(): WfStateStrategy {
    // durable override — NOT `this.state =`
    return new HandleStateStrategy({ store: new AsWfStore({ table }) });
  }
}
app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, MyWfTriggerProvider]));
```

- Default state = **encapsulated** named-strategy registry (no durable rows; idle form can't 410). A step swaps to `store` after first validated input; `storeStrategy()` supplies the durable backend.
- Encapsulated secret defaults to `auth.deriveStateKey("wf-state")` (HKDF, stable across restarts); override `wfStateSecret()` / `wfStateEncapsulatedTtlMs()`.
- `handle()` forwards the `strategy` run-option (else the wf adapter throws `Key "wf.strategyName" is not set`). Token wire field is `token` (default `{ read:['body','query','cookie'], write:'body', name:'wfs' }`).
- `createAuthEmailOutlet({ emailSender, buildMagicLinkUrl, magicLinkTtlMs })` — `buildMagicLinkUrl` is 3-arg `(kind, token, ctx?:{userId?})`.

## Finish envelopes

`finishWf(opts)` / `abortWf(reason, opts)` from `@atscript/moost-wf` (envelope shape — `next:{trigger,action?,primary?,options?}` — owned by that package; load the `atscript-ui-wf` skill for it). Login attaches cookies via `useAuth().buildFinishedCookies(issue)`.

## Bundled forms (19)

`WithInlineConsentForm` (base), `LoginCredentialsForm`, `Select2faForm`, `MfaCodeForm`, `PincodeForm`, `EmailIdentifierForm`, `SetPasswordForm`, `EnrollPickMethodForm`, `EnrollAddressForm`, `EnrollConfirmForm`, `AskEmailForm`, `AskPhoneForm`, `TermsBumpForm`, `ConcurrencyLimitForm`, `InviteForm`, `MagicLinkRequestForm`, `RecoveryModeSelectForm`, `RecoveryFactorForm`, `ChangePasswordForm` (current + new + confirm, with live `AsPasswordRules` readout — the change-password flow's only pause). Replace any per-slot via `opts.forms.<slot>`. Forms carrying `@ui.form.component` → `@atscript/vue-aooth` (`AsConsentArray`/`AsPasswordRules`/`AsQrCode`) — see [spa-components.md](spa-components.md).

## Key imports

```ts
import {
  AuthWorkflow,
  ConsentStore,
  WfTriggerProvider,
  WfTrigger,
  CHANGE_PASSWORD_WORKFLOW,
  createAuthEmailOutlet,
  buildInviteAlreadyAcceptedEnvelope,
  parseInviteRoles,
  stripReservedUserKeys,
  RESERVED_USER_KEYS,
} from "@aooth/auth-moost";
import type {
  AuthWorkflowOpts,
  ResolvedAuthWorkflowOpts,
  AuthDeliveryPayload,
  AuthWfCtx,
  ConsentDescriptor,
  ConsentEvent,
  WfTriggerOpts,
} from "@aooth/auth-moost";
import {
  HandleStateStrategy,
  EncapsulatedStateStrategy,
  type WfStateStrategy,
} from "@moostjs/event-wf";
import { AsWfStore } from "@atscript/moost-wf";
```

## References

| Domain                   | File                                   | When                                                                                 |
| ------------------------ | -------------------------------------- | ------------------------------------------------------------------------------------ |
| Controllers + decorators | [controllers.md](controllers.md)       | `/auth/trigger` + 4 other routes, `useAuth`, 401-vs-403                              |
| SPA rendering            | [spa-components.md](spa-components.md) | render forms client-side; AsQrCode/AsConsentArray/AsPasswordRules; magic-link resume |
| Engine invariants        | [invariants.md](invariants.md)         | cross-package rules                                                                  |

## See also

Docs: https://aoothjs.dev/moost/workflows · canonical conventions: `packages/auth-moost/CLAUDE.md` · source: https://github.com/moostjs/aoothjs
