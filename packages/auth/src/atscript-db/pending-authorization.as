@db.table 'aooth_pending_authorizations'
@db.depth.limit 0
export interface AoothPendingAuthorization {
    /**
     * Opaque server-side handle (PK) — the only thing that rides the URL / wf
     * state. Server-generated UUID in `PendingAuthorizationStoreAtscriptDb.create`.
     */
    @meta.id
    handle: string

    /** The client's validated `redirect_uri` — where the auth code is delivered. */
    redirectUri: string
    /** PKCE S256 challenge; verified against the verifier at `/token`. */
    codeChallenge: string

    /** Registered client id (Tier 2); absent for a public/loopback client. */
    clientId?: string
    /** The client's `state`, echoed back on the redirect so it can correlate. */
    clientState?: string
    /** Granted scope (space-joined). */
    scope?: string
    /** OIDC `nonce`, echoed into the `id_token` (Tier 2). */
    nonce?: string
    /** Mint an `id_token` at `/token` (Tier 2). */
    idToken?: boolean
    /** Mint an access token at `/token`. */
    accessToken?: boolean
    /** The `id_token` `aud` (the registered `client_id`). */
    audience?: string

    /**
     * The grant's `TokenPolicy`, serialized as a JSON string. `TokenPolicy.payload`
     * is an OPEN `Record<string, unknown>` (consumer attenuation), which a closed
     * `@db.json` schema would reject — so the whole policy is stored opaque and
     * (de)serialized at the adapter boundary (`PendingAuthorizationStoreAtscriptDb`).
     */
    tokenPolicy: string

    createdAt: number.timestamp
    /** Lazy-GC'd on read once past. */
    expiresAt: number.timestamp
}
