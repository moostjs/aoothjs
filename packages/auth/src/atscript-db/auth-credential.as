@db.table 'aooth_credentials'
@db.depth.limit 0
export interface AoothAuthCredential {
    /**
     * Opaque token id. Server-generated UUID in `CredentialStoreAtscriptDb.persist`.
     * Also serves as the row PK so `findOne({ filter: { token } })` and
     * `deleteOne(token)` are O(1).
     */
    @meta.id
    token: string

    /** Owner. Indexed for `revokeAllForUser` / `listForUser` scans. */
    @db.index.plain
    userId: string

    issuedAt: number.timestamp
    expiresAt: number.timestamp

    /**
     * "access" | "refresh" discriminant. Stored as a plain string to keep
     * the model adapter-portable — engines that lack an enum type collapse
     * literal unions to strings anyway.
     */
    kind?: string

    /**
     * Custom claims, stored as JSON. Pattern-property shape accepts any key
     * with a scalar value — matches the JWT registered-claim spec (iss, sub,
     * iat, exp, jti, aud, etc.) which are all primitives. Consumers needing
     * nested/structured claims should subclass with an explicit `claims` shape.
     */
    @db.json
    claims?: {
        [/.*/]: string | number | boolean
    }

    /** Display metadata: ip, userAgent, fingerprint, label. */
    @db.json
    metadata?: {
        ip?: string
        userAgent?: string
        fingerprint?: string
        label?: string
    }

    /** Set by refresh-token rotation. */
    parentCredentialId?: string
    rotatedAt?: number.timestamp

    /**
     * Stable session-family id. Minted once at login, copied forward on every
     * rotation. Indexed so a store could group/revoke a family natively (the
     * orchestrator groups in-memory today, but the index is cheap + forward-looking).
     */
    @db.index.plain
    sessionId?: string

    /** Last-activity timestamp; written only under `trackLastSeen`. */
    lastSeenAt?: number.timestamp
}
