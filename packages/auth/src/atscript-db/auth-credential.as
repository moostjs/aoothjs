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

    /** Custom claims, opaque JSON. */
    @db.json
    claims?: {
        [key: string]: any
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
}
