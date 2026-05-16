import { Injectable } from "moost";

export const DEFAULT_INVITE_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Input passed to {@link InviteWorkflowOptions.prepareUser}: the validated
 * invite-step `email` plus the parsed `roles[]` array the workflow computed
 * (empty when the admin did not specify any roles).
 */
export interface InvitePrepareUserInput {
  email: string;
  roles: string[];
}

@Injectable()
export class InviteWorkflowOptions {
  inviteTokenTtlMs: number = DEFAULT_INVITE_TOKEN_TTL_MS;

  /**
   * Called by `InviteWorkflow.accept` immediately before
   * `userService.createUser` to populate consumer-specific required user
   * fields (e.g. `tenantId`) without subclassing the user store. The returned
   * object is forwarded as the `extras` argument to `createUser`.
   */
  prepareUser?: (
    input: InvitePrepareUserInput,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;

  constructor(opts: Partial<InviteWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}
