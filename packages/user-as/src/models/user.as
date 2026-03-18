@db.table 'aooth_users'
export interface AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @db.index.unique 'username_idx'
    username: string

    @db.patch.strategy 'merge'
    password: {
        hash: string
        salt: string
        algorithm: string

        @db.json
        history: { algorithm: string, hash: string }[]

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
        @db.patch.strategy 'merge'
        email: {
            address: string
            confirmed: boolean
        }
        @db.patch.strategy 'merge'
        sms: {
            confirmed: boolean
            number: string
        }
        @db.patch.strategy 'merge'
        totp: {
            secretKey: string
        }
        default: string
        autoSend: boolean
    }
}
