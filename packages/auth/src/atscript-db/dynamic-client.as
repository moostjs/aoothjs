@db.table 'aooth_dynamic_clients'
@db.depth.limit 0
export interface AoothDynamicClient {
    /**
     * Opaque client identifier (PK) — the DCR response `client_id`.
     * Server-generated UUID in `DynamicClientStoreAtscriptDb.create`.
     */
    @meta.id
    clientId: string

    /**
     * Sanitized DCR `client_name` — untrusted registrant-supplied display text
     * for the consent prompt; rendered as a text node only.
     */
    clientName?: string

    /**
     * Validated redirect allowlist, serialized as a JSON string array — same
     * opaque-string pattern as `AoothPendingAuthorization.tokenPolicy` (a
     * string[] column would need engine-specific array support; the adapter
     * (de)serializes at the boundary and matching happens in
     * `DynamicClientPolicy`).
     */
    redirectUris: string

    /**
     * "none" (public — PKCE is the binding) or "client_secret_post"
     * (confidential — a server-minted secret is checked at the token endpoint).
     */
    tokenEndpointAuthMethod: string

    /**
     * SHA-256 hex digest of the minted client_secret — set iff
     * tokenEndpointAuthMethod is "client_secret_post". The plaintext is
     * returned once in the registration response and never stored.
     */
    clientSecretHash?: string

    /** Registered grant types (narrowed to supported), JSON string array. */
    grantTypes: string
    /** Registered response types (narrowed to supported), JSON string array. */
    responseTypes: string

    /** Scope string from registration (space-joined) — an upper bound, not a grant. */
    scope?: string

    createdAt: number.timestamp
    /**
     * Last authorize-request use. Unset ⇒ never used — the GC target of
     * `deleteUnusedBefore` (anonymous /register spam registers but never
     * authorizes). Used rows are never evicted.
     */
    lastUsedAt?: number.timestamp
}
