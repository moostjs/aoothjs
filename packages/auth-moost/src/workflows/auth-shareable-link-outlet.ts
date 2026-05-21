/**
 * `shareableLink` outlet — sibling of `createAuthEmailOutlet`. Builds the
 * magic-link URL the same way the email outlet does, but returns it directly
 * in the admin's HTTP response instead of sending an email.
 *
 * Workflow code emits the request via the generic `outlet('shareableLink', …)`
 * helper from `@moostjs/event-wf`; the trigger provider registers this
 * outlet alongside the HTTP + email outlets so the response surfaces back
 * to the admin's browser.
 */
import type { AuthEmailKind, BuildMagicLinkUrl } from "@aooth/auth";
import type { WfOutlet, WfOutletRequest } from "@moostjs/event-wf";

export interface AuthShareableLinkOutletDeps {
  buildMagicLinkUrl: BuildMagicLinkUrl;
  /** Fallback TTL when the workflow context omits `expiresAtMs`. */
  magicLinkTtlMs: (kind: AuthEmailKind) => number;
}

export function createAuthShareableLinkOutlet(deps: AuthShareableLinkOutletDeps): WfOutlet {
  // `tokenDelivery: "out-of-band"` matches `createEmailOutlet`'s contract —
  // the token is embedded in the URL surfaced to the admin, not echoed to
  // the caller of the trigger request. The field is missing from the
  // `WfOutlet` interface in `@prostojs/wf@0.1.1` (auth-moost's resolved
  // version) but is honored at runtime by `@wooksjs/event-wf` — same shape
  // `createEmailOutlet` returns. Cast through `unknown` to bypass excess-
  // property checking.
  return {
    name: "shareableLink",
    tokenDelivery: "out-of-band",
    async deliver(request: WfOutletRequest, token: string) {
      const template = (request.template ?? "") as AuthEmailKind;
      const context = request.context ?? {};
      const ttlHint = typeof context.expiresAtMs === "number" ? context.expiresAtMs : 0;
      const expiresAt = Date.now() + (ttlHint || deps.magicLinkTtlMs(template));
      const url = deps.buildMagicLinkUrl(template, token);
      return {
        response: {
          sent: true,
          outlet: "shareableLink",
          url,
          expiresAt,
        },
      };
    },
  } as unknown as WfOutlet;
}
