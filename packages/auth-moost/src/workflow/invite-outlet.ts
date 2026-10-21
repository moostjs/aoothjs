import type { WfOutlet } from "@moostjs/event-wf";
import { current, key } from "@wooksjs/event-core";

/** Name of the outlet `AuthWorkflow` pauses on for `inviteDelivery: 'deliver' | 'return-link'`. */
export const INVITE_OUTLET = "invite";

/** Turns the minted resume token into the outlet's HTTP response (after delivering the link). */
type PendingInviteLink = (token: string) => Promise<unknown>;

const pendingInviteLinkKey = key<PendingInviteLink | null>("aooth.invite.pendingLink");

/**
 * Trigger side: reserve the slot on the HTTP event before the workflow runs.
 * Workflow steps run in a child event, and a child's write lands in the
 * nearest context already holding the slot — so the step's callback becomes
 * visible to the `invite` outlet, which runs back on the HTTP event.
 */
export function reservePendingInviteLink(): void {
  current().set(pendingInviteLinkKey, null);
}

/** Step side: register what to do with the token once the pause is persisted. */
export function setPendingInviteLink(fn: PendingInviteLink): void {
  current().set(pendingInviteLinkKey, fn);
}

/**
 * The `invite` outlet (registered by default on `WfTriggerProvider`): hands
 * the resume token to the callback the `send-email` step registered, which
 * builds the link and delivers it (`'deliver'`) or returns it to the issuer
 * (`'return-link'`). The token never rides the response on its own.
 */
export function createInviteOutlet(): WfOutlet {
  return {
    name: INVITE_OUTLET,
    tokenDelivery: "out-of-band",
    async deliver(_request, token) {
      const ctx = current();
      const pending = ctx.has(pendingInviteLinkKey) ? ctx.get(pendingInviteLinkKey) : null;
      if (!pending) {
        throw new Error(
          "The invite outlet has no pending link — the trigger must run through WfTriggerProvider.handle()",
        );
      }
      ctx.set(pendingInviteLinkKey, null);
      return { response: await pending(token) };
    },
  };
}
