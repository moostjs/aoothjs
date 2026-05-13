/**
 * Bridges `@moostjs/event-wf`'s `createEmailOutlet(send)` to the
 * `EmailSender` + `BuildMagicLinkUrl` callbacks carried by
 * {@link MoostAuthWorkflowConfig}.
 *
 * Consumers wire this into their workflow outlet trigger. The recommended
 * shape is TWO triggers — a public one for self-service flows
 * (login, recovery) and an admin-gated one for invite. Mixing them under a
 * single public `allow:` list exposes an unauthenticated invite-email-spam
 * vector via `auth.invite` step 1.
 *
 * ```ts
 * import { createHttpOutlet, HandleStateStrategy } from '@moostjs/event-wf'
 * import { AsWfStore } from '@atscript/moost-wf/store'
 * import { createAuthEmailOutlet } from '@aoothjs/auth-moost'
 *
 * const wfStore = new AsWfStore({ table })
 * const handleStrategy = new HandleStateStrategy({ store: wfStore })
 *
 * // Public: login + recovery (recovery is enumeration-resistant by design).
 * \@Post('wf/trigger')
 * \@Public()
 * async publicTrigger(\@Inject(MoostAuthWorkflowConfig) cfg: MoostAuthWorkflowConfig) {
 *   return this.wf.handleOutlet({
 *     allow: ['auth.login', 'auth.recovery'],
 *     state: handleStrategy,
 *     outlets: [createHttpOutlet(), createAuthEmailOutlet(cfg)],
 *   })
 * }
 *
 * // Admin-only: invite. MUST be guarded.
 * \@Post('admin/wf/invite')
 * \@ArbacAuthorize({ resource: 'user', action: 'invite' })
 * async inviteTrigger(\@Inject(MoostAuthWorkflowConfig) cfg: MoostAuthWorkflowConfig) {
 *   return this.wf.handleOutlet({
 *     allow: ['auth.invite'],
 *     state: handleStrategy,
 *     outlets: [createHttpOutlet(), createAuthEmailOutlet(cfg)],
 *   })
 * }
 * ```
 *
 * Invite-accept resumption: the magic link points the user back at a public
 * route. Either the public trigger above (which already accepts `?wfs=...`
 * resume tokens regardless of `allow:` — `consume(token)` runs before the
 * allow-list check) or a dedicated `allow: []` resume-only route works.
 *
 * The bridge translates the engine's `{ target, template, context, token }`
 * into the typed `AuthEmailEvent` payload. `template` MUST be one of the
 * `AuthEmailKind` values (`'recovery.magicLink'` / `'invite.magicLink'`) or
 * the bridge throws — workflows are responsible for using the right template
 * names.
 */
import type { AuthEmailEvent, AuthEmailKind } from "@aoothjs/auth";
import { createEmailOutlet, type WfOutlet } from "@moostjs/event-wf";

import type { MoostAuthWorkflowConfig } from "../workflow-config";

const KNOWN_KINDS = new Set<string>(["recovery.magicLink", "invite.magicLink", "mfa.code"]);

function isAuthEmailKind(value: string): value is AuthEmailKind {
  return KNOWN_KINDS.has(value);
}

/**
 * Build the email outlet that delivers magic links via the consumer's
 * `EmailSender`. Single-use: pass the same instance into one
 * `handleWfOutletRequest({ outlets })`.
 */
export function createAuthEmailOutlet(wfConfig: MoostAuthWorkflowConfig): WfOutlet {
  return createEmailOutlet(async (opts) => {
    const cfg = wfConfig.config;
    if (!isAuthEmailKind(opts.template)) {
      throw new Error(
        `createAuthEmailOutlet: unknown email template "${opts.template}". ` +
          `Expected one of: ${Array.from(KNOWN_KINDS).join(", ")}.`,
      );
    }
    const template: AuthEmailKind = opts.template;

    // `expiresAtMs` is carried in the workflow context as a relative TTL hint.
    // For absolute `expiresAt` we add it to `Date.now()` at send time so
    // recipients see a real timestamp.
    const ttlHint = typeof opts.context?.expiresAtMs === "number" ? opts.context.expiresAtMs : 0;
    const expiresAt = Date.now() + (ttlHint || cfg.recoveryTokenTtlMs);

    const url = cfg.buildMagicLinkUrl(
      template === "recovery.magicLink" ? "recovery" : "invite",
      opts.token,
    );

    const event: AuthEmailEvent = {
      kind: template,
      recipient: opts.target,
      url,
      expiresAt,
    };
    if (typeof opts.context?.username === "string") {
      event.username = opts.context.username;
    }
    const rolesRaw = opts.context?.roles;
    if (Array.isArray(rolesRaw)) {
      const roles = rolesRaw.filter((r): r is string => typeof r === "string");
      if (roles.length > 0) event.metadata = { roles };
    }

    await cfg.emailSender.send(event);
  });
}
