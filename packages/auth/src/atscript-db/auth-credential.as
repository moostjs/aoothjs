/**
 * The framework-written credential-metadata envelope keys — the `.as` twin of
 * `CredentialMetadata` in `@aooth/auth` (keep the two in sync). The bundled
 * row model ships NO metadata column; a consumer who wants metadata persisted
 * declares their own `@aooth.auth.metadata @db.json` field and builds its shape
 * by INTERSECTING this type with their extension keys:
 *
 *     import { AoothAuthCredential, AoothCredentialMetadataBase } from '@aooth/auth/atscript-db/model'
 *
 *     @aooth.auth.metadata
 *     @db.json
 *     metadata?: AoothCredentialMetadataBase & { geoLat?: number, geoLon?: number }
 *
 * That keeps one source of truth for the framework keys: when a future aooth
 * release adds an envelope key here, consumer schemas pick it up on upgrade
 * instead of silently rejecting it from their hand-mirrored closed shape.
 */
export type AoothCredentialMetadataBase = {
    /** Client IP captured at issue time (default `resolveIssueMetadata`). */
    ip?: string
    /** Raw User-Agent captured at issue time. */
    userAgent?: string
    /** Consumer-supplied device fingerprint (`IssueOptions.fingerprint`). */
    fingerprint?: string
    /** Human-readable session label. */
    label?: string
    /**
     * Semantic credential kind (e.g. "cli-session" / "pat") — distinct from
     * the internal access/refresh `kind` column on the row.
     */
    credentialKind?: string
}

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

    // NO metadata column here — credential metadata is CONSUMER-DECLARED.
    // Declare a fully-typed `@db.json` field on your extending model (the
    // runtime/validation twin of your `CredentialMetadata` declaration merge)
    // and mark it `@aooth.auth.metadata`; without one, the atscript-db store
    // persists no metadata (memory/JWT stores are unaffected). Build the shape
    // as `AoothCredentialMetadataBase & { ...your keys }` (exported above) so
    // the framework-written keys stay single-sourced.

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
