/**
 * Bridges `@moostjs/event-wf`'s `createEmailOutlet(send)` to the consumer's
 * `EmailSender` + `BuildMagicLinkUrl` callbacks.
 *
 * Wire this into the workflow outlet trigger. Authorization is the workflow
 * class's responsibility (`@ArbacResource` + `@ArbacAction`); the trigger
 * route stays `@Public()`.
 *
 * ```ts
 * import { createHttpOutlet, HandleStateStrategy } from '@moostjs/event-wf'
 * import { AsWfStore } from '@atscript/moost-wf/store'
 * import { createAuthEmailOutlet } from '@aooth/auth-moost'
 *
 * const wfStore = new AsWfStore({ table })
 * const handleStrategy = new HandleStateStrategy({ store: wfStore })
 * const emailOutletDeps = {
 *   emailSender,
 *   buildMagicLinkUrl,
 *   magicLinkTtlMs: () => 3600_000,
 * }
 *
 * \@Post('wf/trigger')
 * \@Public()
 * async trigger() {
 *   return this.wf.handleOutlet({
 *     allow: ['auth.login', 'auth.recovery', 'auth.invite'],
 *     state: handleStrategy,
 *     outlets: [createHttpOutlet(), createAuthEmailOutlet(emailOutletDeps)],
 *   })
 * }
 * ```
 */
import type { AuthEmailEvent, AuthEmailKind, BuildMagicLinkUrl, EmailSender } from "@aooth/auth";
import { createEmailOutlet, type WfOutlet } from "@moostjs/event-wf";

export interface AuthEmailOutletDeps {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  /** Fallback TTL when the workflow context omits `expiresAtMs`. */
  magicLinkTtlMs: (kind: AuthEmailKind) => number;
}

/**
 * Build the email outlet that delivers magic links via the consumer's
 * `EmailSender`. Single-use: pass the same instance into one
 * `handleWfOutletRequest({ outlets })`.
 */
export function createAuthEmailOutlet(deps: AuthEmailOutletDeps): WfOutlet {
  return createEmailOutlet(async (opts) => {
    // The downstream `emailSender.send(...)` types `kind` as `AuthEmailKind`.
    // Cast once here so consumers can add new magic-link kinds without
    // forking the outlet — typing surfaces any mismatch at the EmailSender.
    const template = opts.template as AuthEmailKind;

    // `expiresAtMs` is carried in the workflow context as a relative TTL hint.
    // For absolute `expiresAt` we add it to `Date.now()` at send time so
    // recipients see a real timestamp.
    const ttlHint = typeof opts.context?.expiresAtMs === "number" ? opts.context.expiresAtMs : 0;
    const expiresAt = Date.now() + (ttlHint || deps.magicLinkTtlMs(template));

    const url = deps.buildMagicLinkUrl(template, opts.token, {
      userId: typeof opts.context?.userId === "string" ? opts.context.userId : undefined,
    });

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
