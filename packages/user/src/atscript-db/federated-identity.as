// Account-linking table: one external-provider account → exactly one aooth
// user. The genuinely new piece of persistent state for federated login —
// the `(provider, subject) → userId` map (RFC IDP.md §3.3). Shipped concrete
// (own `@db.table`), like `AoothAuthCredential`; consumers can extend it with
// `extends AoothFederatedIdentity {}` to re-own the table name, exactly as
// `DemoAuthCredential` does.
@db.table 'aooth_federated_identities'
@db.depth.limit 0
export interface AoothFederatedIdentity {
    // Surrogate PK — lets a row be addressed (unlink-by-id) / extended.
    @meta.id
    @db.default.uuid
    id: string

    // Composite identity key. The SAME index name on both fields collapses
    // into ONE compound UNIQUE index (atscript-db groups index fields by
    // (type, name)) — so a provider account maps to at most one row, which is
    // the anti-account-takeover guarantee (RFC §1 note #4, §4).
    @db.index.unique 'provider_subject_idx'
    provider: string                 // 'google' | 'github' | 'oidc:<issuer>' ...
    @db.index.unique 'provider_subject_idx'
    subject: string                  // the IdP's stable subject id (`sub`)

    // Owner — the user's stable surrogate `id`. A PLAIN indexed string, NOT a
    // `@db.rel.FK`: `@aooth/user` cannot know the consumer's concrete user
    // table (`AoothUserCredentials` is an abstract, table-less base), so this
    // mirrors `AoothAuthCredential.userId`. Cross-row cleanup is the explicit
    // `FederatedIdentityStore.deleteAllForUser` (GDPR), not a DB cascade.
    // Consumers wanting a hard FK + cascade re-declare it in their subclass.
    @db.index.plain
    userId: string

    // Display snapshots — refreshed by `touchLogin` on each federated login;
    // NOT join keys (the stable join is always `(provider, subject)`). A
    // provider's snapshot email (e.g. Apple Private Relay) may differ from the
    // user-row `email` handle, so these live here per-identity.
    email?: string
    emailVerified?: boolean
    displayName?: string
    avatarUrl?: string

    linkedAt: number.timestamp
    lastLoginAt?: number.timestamp
}
