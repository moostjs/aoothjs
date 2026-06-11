@db.table 'aooth_auth_codes'
@db.depth.limit 0
export interface AoothAuthCode {
    /**
     * Opaque single-use code (PK). Server-generated UUID in
     * `AuthCodeStoreAtscriptDb.mint`. Consumed atomically at `/token`: the
     * `deleteOne(code)` whose `deletedCount === 1` is the single-use claim, so a
     * concurrent double-redeem (or back-button replay) yields it to one caller.
     */
    @meta.id
    code: string

    /** The user the login workflow authenticated. */
    userId: string
    /** PKCE S256 challenge from the originating authorize request. */
    codeChallenge: string
    /** The client's `redirect_uri` (bound; the code is meaningless elsewhere). */
    redirectUri: string

    /** Registered client id (Tier 2); absent for a public/loopback client. */
    clientId?: string
    /** Granted scope (space-joined). */
    scope?: string
    /** RFC 8707 `resource` indicator (recorded; consistency-checked at /token). */
    resource?: string
    /** OIDC `nonce`, echoed into the `id_token` (Tier 2). */
    nonce?: string
    /** Mint an `id_token` at `/token` (Tier 2). */
    idToken?: boolean
    /** Mint an access token at `/token`. */
    accessToken?: boolean
    /** The `id_token` `aud` (the registered `client_id`). */
    audience?: string

    /**
     * The grant's `TokenPolicy`, serialized as a JSON string — see
     * `AoothPendingAuthorization.tokenPolicy` for why it is opaque, not `@db.json`.
     */
    tokenPolicy: string

    /** Very short (≈ 30–60 s). Past-expiry rows are rejected on consume. */
    expiresAt: number.timestamp
}
