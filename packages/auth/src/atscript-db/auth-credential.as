/**
 * Recursive JSON value. Lets `claims` carry structured/nested custom claims
 * (e.g. the reserved `arbac` attenuation namespace from `@aooth/arbac-moost`),
 * not only the JWT-registered scalar claims — while STILL being validated by
 * the store (vs. an opaque blob). Scalars remain valid, so existing scalar
 * claims round-trip unchanged.
 */
export type TJsonValue = string | number | boolean | TJsonValue[] | { [/.*/]: TJsonValue }

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
     * Custom claims, stored as JSON. Values are full JSON (`TJsonValue`), so
     * besides the JWT registered scalar claims (iss, sub, iat, exp, jti, aud)
     * a key may carry a nested/structured value — notably the reserved `arbac`
     * attenuation namespace (`{ roles?: string[]; attrs?: {...} }`) consumed by
     * `@aooth/arbac-moost`. Scalars remain valid, so existing claims are
     * unaffected.
     */
    @db.json
    claims?: {
        [/.*/]: TJsonValue
    }
I 
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
