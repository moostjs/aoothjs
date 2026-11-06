import type { WfOutlet } from "@moostjs/event-wf";
import { useLogger } from "moost";

/** Name of the outlet `AuthWorkflow` pauses on to send a recovery or sign-in magic link. */
export const MAGIC_LINK_OUTLET = "magic-link";

/**
 * Name of the state strategy a magic link's pause is persisted under
 * (registered by `WfTriggerProvider`). Its own keyspace makes the trigger mint
 * a fresh handle for the link, and the next pause swaps off it again — so the
 * emailed token is consumed by its first use and never becomes the
 * continuation of the flow.
 */
export const MAGIC_LINK_STRATEGY = "magic-link";

/** The answer of every magic-link request, sent or not: nothing tells the outcomes apart. */
const SENT = Object.freeze({ sent: true, outlet: "email" });

/**
 * The `magic-link` outlet (registered by default on `WfTriggerProvider`). The
 * step decides whether a link goes out (`context.deliver`); when it does, the
 * link is handed to the app's `email` outlet (`createAuthEmailOutlet`) with
 * the step's template (`recovery.magicLink` / `login.magicLink`). Known and
 * unknown identifiers get the same answer, and a failed delivery is logged,
 * not reported — the response never says whether an account exists.
 *
 * @param emailOutlet - resolves the app's `email` outlet at delivery time.
 */
export function createMagicLinkOutlet(emailOutlet: () => WfOutlet | undefined): WfOutlet {
  return {
    name: MAGIC_LINK_OUTLET,
    tokenDelivery: "out-of-band",
    async deliver(request, token) {
      // Checked for every request, sent or not, so a missing email outlet
      // fails the same way for known and unknown identifiers.
      const email = emailOutlet();
      if (!email) {
        throw new Error(
          "Magic links are sent through the `email` outlet — append createAuthEmailOutlet(...) to WfTriggerProvider.outlets",
        );
      }
      const { deliver, ...context } = request.context ?? {};
      if (deliver === true && request.target) {
        try {
          await email.deliver({ ...request, outlet: "email", context }, token);
        } catch (err) {
          useLogger("aooth:magic-link").error("magic link delivery failed", err);
        }
      }
      return { response: { ...SENT } };
    },
  };
}
