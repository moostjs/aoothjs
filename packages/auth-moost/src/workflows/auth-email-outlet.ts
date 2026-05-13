/**
 * Bridges `@moostjs/event-wf`'s `createEmailOutlet(send)` to the
 * `EmailSender` + `BuildMagicLinkUrl` callbacks carried by
 * {@link MoostAuthWorkflowConfig}.
 *
 * Consumers wire this into their workflow outlet trigger:
 *
 * ```ts
 * import { createHttpOutlet, handleWfOutletRequest, HandleStateStrategy } from '@moostjs/event-wf'
 * import { AsWfStore } from '@atscript/moost-wf/store'
 * import { createAuthEmailOutlet } from '@aoothjs/auth-moost'
 *
 * const wfStore = new AsWfStore({ table })
 * const handleStrategy = new HandleStateStrategy({ store: wfStore })
 *
 * \@Post('wf/trigger')
 * async trigger(\@Inject(MoostAuthWorkflowConfig) cfg: MoostAuthWorkflowConfig) {
 *   return this.wf.handleOutlet({
 *     allow: ['auth.login', 'auth.recovery', 'auth.invite'],
 *     state: handleStrategy,
 *     outlets: [createHttpOutlet(), createAuthEmailOutlet(cfg)],
 *   })
 * }
 * ```
 *
 * The bridge translates the engine's `{ target, template, context, token }`
 * into the typed `AuthEmailEvent` payload. `template` MUST be one of the
 * `AuthEmailKind` values (`'recovery.magicLink'` / `'invite.magicLink'`) or
 * the bridge throws — workflows are responsible for using the right template
 * names.
 */
import { createEmailOutlet, type WfOutlet } from "@moostjs/event-wf";

import type { AuthEmailEvent, AuthEmailKind } from "../email";
import type { MoostAuthWorkflowConfig } from "../workflow-config";

const KNOWN_KINDS: ReadonlySet<AuthEmailKind> = new Set([
  "recovery.magicLink",
  "invite.magicLink",
  "mfa.code",
]);

/**
 * Build the email outlet that delivers magic links via the consumer's
 * `EmailSender`. Single-use: pass the same instance into one
 * `handleWfOutletRequest({ outlets })`.
 */
export function createAuthEmailOutlet(wfConfig: MoostAuthWorkflowConfig): WfOutlet {
  return createEmailOutlet(async (opts) => {
    const cfg = wfConfig.config;
    const template = opts.template as AuthEmailKind;
    if (!KNOWN_KINDS.has(template)) {
      throw new Error(
        `createAuthEmailOutlet: unknown email template "${opts.template}". ` +
          `Expected one of: ${Array.from(KNOWN_KINDS).join(", ")}.`,
      );
    }

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
    if (Array.isArray(opts.context?.roles)) {
      event.metadata = { roles: opts.context.roles as string[] };
    }

    await cfg.emailSender.send(event);
  });
}
