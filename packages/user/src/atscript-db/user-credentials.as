export interface AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @db.index.unique 'username_idx'
    username: string

    @db.index.unique 'email_idx'
    email?: string

    @db.column.version
    version: number.int

    @db.patch.strategy 'merge'
    password: {
        hash: string

        history: string[]

        lastChanged: number.timestamp
        isInitial: boolean
    }

    @db.patch.strategy 'merge'
    account: {
        active: boolean
        locked: boolean
        lockReason: string
        lockEnds: number.timestamp
        failedLoginAttempts: number
        lastLogin: number.timestamp
        pendingInvitation?: boolean
    }

    @db.patch.strategy 'merge'
    mfa: {
        methods: { name: string, confirmed: boolean, value: string, lastUsedWindow?: number.int }[]

        defaultMethod: string
        autoSend: boolean
    }

    @db.patch.strategy 'merge'
    trustedDevices?: {
        token: string
        ip?: string
        issuedAt: number.timestamp
        expiresAt: number.timestamp
        name?: string
    }[]
}
