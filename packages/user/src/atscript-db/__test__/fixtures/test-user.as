@db.table 'aooth_users'
export interface AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @db.index.unique 'username_idx'
    username: string

    @db.column.version
    version: number.int

    @db.patch.strategy 'merge'
    password: {
        hash: string

        @db.json
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
    }

    @db.patch.strategy 'merge'
    mfa: {
        methods: { name: string, confirmed: boolean, value: string }[]

        defaultMethod: string
        autoSend: boolean
    }
}
