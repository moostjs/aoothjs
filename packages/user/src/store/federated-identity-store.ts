/**
 * Display fields snapshotted from an IdP profile onto a federated-identity row.
 * Refreshed on each login via {@link FederatedIdentityStore.touchLogin}; never
 * a join key (the stable join is `(provider, subject)`). Phase-2's
 * `NormalizedProfile` (in `@aooth/idp`) is a structural superset of this — it
 * is declared HERE rather than imported so `@aooth/user` keeps no dependency on
 * the layer above it.
 */
export interface FederatedProfileSnapshot {
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
}

/**
 * Copy only the DEFINED display fields — so a `touchLogin` / `link` with a
 * partial profile (e.g. Apple omitting the email on a repeat login) never
 * overwrites a stored value with `undefined`. Shared by every
 * {@link FederatedIdentityStore} impl.
 */
export function pickDefinedProfile(src: FederatedProfileSnapshot): FederatedProfileSnapshot {
  const out: FederatedProfileSnapshot = {};
  if (src.email !== undefined) out.email = src.email;
  if (src.emailVerified !== undefined) out.emailVerified = src.emailVerified;
  if (src.displayName !== undefined) out.displayName = src.displayName;
  if (src.avatarUrl !== undefined) out.avatarUrl = src.avatarUrl;
  return out;
}

/**
 * A persisted federated-identity row: one external-provider account
 * (`provider` + the IdP's stable `subject`) linked to exactly one aooth user
 * (`userId` = the user's surrogate `id`). Mirrors the shipped
 * `AoothFederatedIdentity` `.as` model by construction.
 */
export interface FederatedIdentity extends FederatedProfileSnapshot {
  /** Surrogate PK. Server-assigned (`@db.default.uuid` / `randomUUID`). */
  id: string;
  provider: string;
  subject: string;
  /** Owner — the user's stable surrogate `id`. */
  userId: string;
  /** When the link was first created. */
  linkedAt: number;
  /** Last federated login through this identity; absent until first `touchLogin`. */
  lastLoginAt?: number;
}

/**
 * Input to {@link FederatedIdentityStore.link} — the identity keys + owner plus
 * an optional first-login profile snapshot. `id` and `linkedAt` are assigned by
 * the store.
 */
export interface NewFederatedIdentity extends FederatedProfileSnapshot {
  provider: string;
  subject: string;
  userId: string;
}

/**
 * Storage seam for the account-linking table (RFC IDP.md §3.3). The stable
 * lookup key is the composite `(provider, subject)`; a user may own many rows
 * (one per linked provider account), so `userId` reads return a list.
 *
 * In-memory + atscript-db implementations ship alongside; the abstract surface
 * keeps the federated-login core (`@aooth/idp`, phase 2) storage-agnostic.
 */
export abstract class FederatedIdentityStore {
  /** Resolve a provider account to its linked row, or `null`. The federated-login hot path. */
  abstract find(provider: string, subject: string): Promise<FederatedIdentity | null>;
  /** All identities linked to a user — the "connected accounts" view. */
  abstract listForUser(userId: string): Promise<FederatedIdentity[]>;
  /**
   * Link a provider account to a user. Throws `UserAuthError("ALREADY_EXISTS")`
   * when `(provider, subject)` is already linked — to ANY user — which is the
   * DB-enforced guarantee that one provider account maps to one aooth user.
   */
  abstract link(rec: NewFederatedIdentity): Promise<FederatedIdentity>;
  /**
   * Remove a single provider link. Returns `true` when a row was removed,
   * `false` when `(provider, subject)` was not linked. (The "don't strand the
   * user without a usable credential" guard lives in the service layer, not
   * here — this is the raw delete.)
   */
  abstract unlink(provider: string, subject: string): Promise<boolean>;
  /**
   * Stamp `lastLoginAt = now` and merge any DEFINED `profile` fields onto the
   * row. Profile is optional and merged field-by-field, so a provider that
   * omits the email on a repeat login (e.g. Apple after the first auth) never
   * nulls the stored snapshot. No-op when `(provider, subject)` is not linked.
   */
  abstract touchLogin(
    provider: string,
    subject: string,
    profile?: FederatedProfileSnapshot,
  ): Promise<void>;
  /**
   * Remove every identity linked to a user — GDPR hard-delete / "disconnect
   * everything". Returns the number of rows removed. The app-level complement
   * to a DB `onDelete cascade` (which this design deliberately does not use —
   * `userId` is a plain column, not an FK).
   */
  abstract deleteAllForUser(userId: string): Promise<number>;
}
