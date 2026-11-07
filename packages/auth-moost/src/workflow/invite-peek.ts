import type { UserService } from "@aooth/user";
import { normalizeWfId } from "@moostjs/event-wf";

import { STATE_EXPIRES_KEY, type WfTriggerProvider } from "../wf-trigger/provider";
import type { AuthWfCtx } from "./auth-workflow.ctx";

/** Id of the invite workflow (`AuthWorkflow`'s `@Workflow("auth/invite/start")`). */
const INVITE_WORKFLOW = "auth/invite/start";

/** What {@link peekInvite} tells about a pending invite — safe to show its holder. */
export interface InvitePeek {
  /** The invited address. */
  email: string;
  /** User id of the issuer — set when the invite was issued from a signed-in session. */
  invitedBy?: string;
  /** Roles the invite grants, when it grants any. */
  roles?: string[];
  /** When the link stops working (ms since epoch), when known. */
  expiresAt?: number;
}

/**
 * Read what an invite link (its `wfs` token) is for — the invited address,
 * the issuer, the roles and the link's expiry — WITHOUT consuming it, e.g. to
 * show "Ann invited you as an editor" on the invite page before the invitee
 * acts. Resolves the token through {@link WfTriggerProvider.peek}, then checks
 * it against the account: an invite that was replaced by a re-invite, accepted,
 * cancelled or that is not an invite link reads as `null`, the same as an
 * unknown or expired token.
 *
 * Mount it on your own route and rate-limit that route like invite
 * redemption — e.g. `@RateLimit("30/5m", { id: "app.invite-info" })`.
 */
export async function peekInvite(
  token: string,
  deps: { trigger: WfTriggerProvider; users: UserService },
): Promise<InvitePeek | null> {
  const state = await deps.trigger.peek(token);
  if (!state || normalizeWfId(state.schemaId) !== INVITE_WORKFLOW) return null;
  const ctx = state.context as AuthWfCtx | undefined;
  const admin = ctx?.admin;
  // Only the invitee's side of the flow: the link was sent for an account.
  if (!ctx?.subject || !ctx.email || !admin?.emailDispatched) return null;
  const user = await deps.users.findByIdentifier(ctx.subject);
  if (!user?.account?.pendingInvitation) return null;
  // A re-invite rotated the account's marker away from this link's (`!= null`:
  // an invite issued before 0.2 has no marker on either side).
  const current = user.account.inviteNonce;
  if (current != null && current !== admin.inviteNonce) return null;
  const expiresAt = state.meta?.[STATE_EXPIRES_KEY];
  return {
    email: ctx.email,
    ...(admin.invitedBy && { invitedBy: admin.invitedBy }),
    ...(admin.roles && admin.roles.length > 0 && { roles: admin.roles }),
    ...(typeof expiresAt === "number" && { expiresAt }),
  };
}
