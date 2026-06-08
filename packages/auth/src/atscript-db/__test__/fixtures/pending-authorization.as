// Test fixture — mirrors `src/atscript-db/pending-authorization.as`. Compiled by
// `prepareFixtures()` so the integration spec can import the runtime metadata
// class and build a real `@atscript/db` table. Keep in sync with the shipped model.
@db.table 'aooth_pending_authorizations'
@db.depth.limit 0
export interface AoothPendingAuthorization {
    @meta.id
    handle: string

    redirectUri: string
    codeChallenge: string

    clientId?: string
    clientState?: string
    scope?: string
    nonce?: string
    idToken?: boolean
    accessToken?: boolean
    audience?: string

    tokenPolicy: string

    createdAt: number.timestamp
    expiresAt: number.timestamp
}
