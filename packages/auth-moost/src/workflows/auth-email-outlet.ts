/**
 * Bridges `@moostjs/event-wf`'s `createEmailOutlet(send)` to the consumer's
 * `EmailSender` + `BuildMagicLinkUrl` callbacks.
 *
 * Consumers wire this into their workflow outlet trigger. Recommended shape:
 * two triggers — a public one for self-service flows (login, recovery) and an
 * admin-gated one for invite. Mixing them under a single public `allow:` list
 * exposes an unauthenticated invite-email-spam vector.
 *
 * ```ts
 * import { createHttpOutlet, HandleStateStrategy } from '@moostjs/event-wf'
 * import { AsWfStore } from '@atscript/moost-wf/store'
 * import { createAuthEmailOutlet } from '@aoothjs/auth-moost'
 *
 * const wfStore = new AsWfStore({ table })
 * const handleStrategy = new HandleStateStrategy({ store: wfStore })
 * const emailOutletDeps = { emailSender, buildMagicLinkUrl, recoveryTokenTtlMs: 3600_000 }
 *
 * // Public: login + recovery (recovery is enumeration-resistant by design).
 * \@Post('wf/trigger')
 * \@Public()
 * async publicTrigger() {
 *   return this.wf.handleOutlet({
 *     allow: ['auth.login', 'auth.recovery'],
 *     state: handleStrategy,
 *     outlets: [createHttpOutlet(), createAuthEmailOutlet(emailOutletDeps)],
 *   })
 * }
 *
 * // Admin-only: invite. MUST be guarded.
 * \@Post('admin/wf/invite')
 * \@ArbacAuthorize({ resource: 'user', action: 'invite' })
 * async inviteTrigger() {
 *   return this.wf.handleOutlet({
 *     allow: ['auth.invite'],
 *     state: handleStrategy,
 *     outlets: [createHttpOutlet(), createAuthEmailOutlet(emailOutletDeps)],
 *   })
 * }
 * ```
 */
import type { AuthEmailEvent, AuthEmailKind, BuildMagicLinkUrl, EmailSender } from "@aoothjs/auth";
import { createEmailOutlet, type WfOutlet } from "@moostjs/event-wf";

const KNOWN_KINDS = new Set<string>(["recovery.magicLink", "invite.magicLink", "mfa.code"]);

function isAuthEmailKind(value: string): value is AuthEmailKind {
  return KNOWN_KINDS.has(value);
}

export interface AuthEmailOutletDeps {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  /** Fallback TTL when the workflow context omits `expiresAtMs`. */
  recoveryTokenTtlMs: number;
}

/**
 * Build the email outlet that delivers magic links via the consumer's
 * `EmailSender`. Single-use: pass the same instance into one
 * `handleWfOutletRequest({ outlets })`.
 */
export function createAuthEmailOutlet(deps: AuthEmailOutletDeps): WfOutlet {
  return createEmailOutlet(async (opts) => {
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
    const expiresAt = Date.now() + (ttlHint || deps.recoveryTokenTtlMs);

    const url = deps.buildMagicLinkUrl(
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

    await deps.emailSender.send(event);
  });
}
