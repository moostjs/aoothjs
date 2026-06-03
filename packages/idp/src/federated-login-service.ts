import {
  type FederatedIdentity,
  type FederatedIdentityStore,
  type FederatedProfileSnapshot,
  type NewFederatedIdentity,
  UserAuthError,
  type UserService,
  pickDefinedProfile,
} from "@aooth/user";
import {
  type FederatedPolicy,
  type NormalizedProfile,
  type ResolveOutcome,
  type ResolvedFederatedPolicy,
  resolveFederatedPolicy,
} from "./types";

export interface FederatedLoginServiceDeps<T extends object = object> {
  /** Concrete user orchestrator (RFC: idp depends on the concrete class). */
  users: UserService<T>;
  /** The account-linking store from `@aooth/user` (memory or atscript-db). */
  federated: FederatedIdentityStore;
  /** Account-matching policy (RFC §4). Safe defaults applied. */
  policy?: FederatedPolicy;
}

/**
 * The core federated-login logic (RFC §3.5): map a verified provider profile to
 * an aooth user id. Pure orchestration over `UserService` + `FederatedIdentityStore`
 * — no HTTP, no workflow, no token issuance (those are phase 3). Account-state
 * gating, MFA, and consent are NOT done here; they run as the existing login
 * workflow tail after the phase-3 `oauth-exchange` step sets the subject.
 *
 * Generic over the user shape `T` so a consumer's `UserService<DemoUser>` plugs
 * in directly; `resolveUser` only reads base `UserCredentials` fields.
 */
export class FederatedLoginService<T extends object = object> {
  private readonly users: UserService<T>;
  private readonly federated: FederatedIdentityStore;
  readonly policy: ResolvedFederatedPolicy;

  constructor(deps: FederatedLoginServiceDeps<T>) {
    this.users = deps.users;
    this.federated = deps.federated;
    this.policy = resolveFederatedPolicy(deps.policy);
  }

  /**
   * Resolve a verified {@link NormalizedProfile} to an outcome (decision #1):
   *
   * 1. **Known** `(provider, subject)` → `linked`.
   * 2. **Email match** (fresh verified email via `findByHandle`):
   *    - `auto-link-if-verified` + trusted + verified → link → `auto-linked`;
   *    - otherwise (incl. `require-interactive-link`, or auto-link conditions
   *      unmet) → `needs-link` (caller completes via {@link linkIdentity}).
   *    - `create-separate` ignores the match and falls to (3).
   * 3. **New** → `denied` if `allowSignup === false`; else create + activate +
   *    link → `created`.
   *
   * Every resolved outcome (`linked`/`auto-linked`/`created`) stamps
   * `lastLoginAt` + refreshes the row's display snapshot via `touchLogin`.
   */
  async resolveUser(profile: NormalizedProfile): Promise<ResolveOutcome> {
    // 1. Known identity — the hot path.
    const known = await this.federated.find(profile.provider, profile.subject);
    if (known) {
      await this.touch(profile);
      return { kind: "linked", userId: known.userId, isNew: false };
    }

    // 2. Email match — only meaningful with a fresh email and not create-separate.
    if (profile.email && this.policy.emailMatch !== "create-separate") {
      const candidate = await this.users.findByHandle(profile.email);
      if (candidate) {
        if (this.policy.emailMatch === "auto-link-if-verified" && this.canAutoLink(profile)) {
          await this.federated.link(this.newIdentity(profile, candidate.id));
          await this.touch(profile);
          return { kind: "auto-linked", userId: candidate.id, isNew: false };
        }
        // require-interactive-link, or auto-link conditions unmet → never silently
        // merge or duplicate; surface the candidate for proof-of-control.
        return { kind: "needs-link", candidateUserId: candidate.id };
      }
    }

    // 3. New account.
    if (!this.policy.allowSignup) return { kind: "denied", reason: "signup-disabled" };
    const userId = await this.createFederatedUser(profile);
    // A federated signup IS the activation — the IdP vouched for the identity,
    // so the phase-3 active/locked gate would otherwise reject the fresh
    // (inactive-by-default) account.
    await this.users.activateAccount(userId);
    await this.federated.link(this.newIdentity(profile, userId));
    await this.touch(profile);
    return { kind: "created", userId, isNew: true };
  }

  /**
   * Complete an interactive link (the `needs-link` outcome): attach
   * `(provider, subject)` to an **already-authenticated** `userId`. Idempotent
   * when it is already that user's. Throws `UserAuthError('ALREADY_EXISTS')`
   * when the identity is already linked to a DIFFERENT user — the
   * confused-deputy / account-injection guard (RFC §4).
   *
   * The CSRF / state↔session-userId binding that proves the request truly
   * speaks for `userId` is the phase-3 controller's responsibility.
   */
  async linkIdentity(params: {
    provider: string;
    subject: string;
    userId: string;
    profile?: FederatedProfileSnapshot;
  }): Promise<FederatedIdentity> {
    const existing = await this.federated.find(params.provider, params.subject);
    if (existing) {
      if (existing.userId === params.userId) {
        await this.federated.touchLogin(
          params.provider,
          params.subject,
          params.profile ? pickDefinedProfile(params.profile) : undefined,
        );
        return existing;
      }
      throw new UserAuthError(
        "ALREADY_EXISTS",
        "This provider account is linked to a different user",
      );
    }
    const rec: NewFederatedIdentity = {
      provider: params.provider,
      subject: params.subject,
      userId: params.userId,
      ...(params.profile ? pickDefinedProfile(params.profile) : {}),
    };
    return this.federated.link(rec);
  }

  // --- internals -------------------------------------------------------

  /** Email-verified AND the provider is explicitly trusted (RFC §4). */
  private canAutoLink(profile: NormalizedProfile): boolean {
    return (
      profile.emailVerified === true &&
      this.policy.trustEmailVerifiedFrom.includes(profile.provider)
    );
  }

  /**
   * Create a fresh user for an unmatched identity. Tries the policy username;
   * on an `ALREADY_EXISTS` conflict falls back to the federated-unique
   * `${provider}:${subject}`. Deliberately does NOT set the account `email`
   * handle — promoting a provider email to the unique login handle is a gated
   * phase-3 concern; the verified email is kept on the federated row instead.
   */
  private async createFederatedUser(profile: NormalizedProfile): Promise<string> {
    const desired = this.policy.usernameStrategy(profile);
    const fallback = `${profile.provider}:${profile.subject}`;
    try {
      const user = await this.users.createUser(desired);
      return user.id;
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS" && desired !== fallback) {
        const user = await this.users.createUser(fallback);
        return user.id;
      }
      throw err;
    }
  }

  private newIdentity(profile: NormalizedProfile, userId: string): NewFederatedIdentity {
    return {
      provider: profile.provider,
      subject: profile.subject,
      userId,
      ...pickDefinedProfile(profile),
    };
  }

  private touch(profile: NormalizedProfile): Promise<void> {
    return this.federated.touchLogin(
      profile.provider,
      profile.subject,
      pickDefinedProfile(profile),
    );
  }
}
