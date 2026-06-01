// Demo-local credential row model — mirrors `AoothAuthCredential` from
// `@aooth/auth/atscript-db`. Declared in the demo's own `src` so `asc`
// (rootDir: src) compiles it and `DbSpace.getTable(DemoAuthCredential)`
// returns a runtime table. `CredentialStoreAtscriptDb` matches it structurally
// (its `AuthCredentialTable` surface is by-shape), so the demo authenticates
// against a real, enumerable store — which is what makes the "active sessions"
// panel (listSessions / revokeSession / revokeOtherSessions) work end-to-end.
@db.table 'aooth_credentials'
@db.depth.limit 0
export interface DemoAuthCredential {
    @meta.id
    token: string

    @db.index.plain
    userId: string

    issuedAt: number.timestamp
    expiresAt: number.timestamp

    kind?: string

    @db.json
    claims?: {
        [/.*/]: string | number | boolean
    }

    @db.json
    metadata?: {
        ip?: string
        userAgent?: string
        fingerprint?: string
        label?: string
    }

    parentCredentialId?: string
    rotatedAt?: number.timestamp

    @db.index.plain
    sessionId?: string

    lastSeenAt?: number.timestamp
}
