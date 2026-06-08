// Test fixture — mirrors `src/atscript-db/auth-code.as`. Compiled by
// `prepareFixtures()` for the integration spec. Keep in sync with the shipped model.
@db.table 'aooth_auth_codes'
@db.depth.limit 0
export interface AoothAuthCode {
    @meta.id
    code: string

    userId: string
    codeChallenge: string
    redirectUri: string

    clientId?: string
    scope?: string
    nonce?: string
    idToken?: boolean
    accessToken?: boolean
    audience?: string

    tokenPolicy: string

    expiresAt: number.timestamp
}
