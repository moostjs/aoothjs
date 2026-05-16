import { Injectable } from "moost";

export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;

@Injectable()
export class RecoveryWorkflowOptions {
  recoveryTokenTtlMs: number = DEFAULT_RECOVERY_TOKEN_TTL_MS;

  /**
   * Resolves the recovery-step `email` input to the `username` (user-id) that
   * `UserService.getUser` expects. Apps whose user model separates `username`
   * and `email` MUST provide this; otherwise `RecoveryWorkflow.requestRecovery`
   * falls back to using the email as the username, silently missing users
   * whose `username !== email`. Return `null` when no user matches that email.
   */
  emailToUserId?: (email: string) => Promise<string | null> | string | null;

  constructor(opts: Partial<RecoveryWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}
