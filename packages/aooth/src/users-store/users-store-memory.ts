import { TCumulativeChanges, TAoothUserCredentials } from '../types'
import { UsersStore } from './users-store'
import { deepClone, setValue } from '../utils/get-set'

export class UsersStoreMemory extends UsersStore {
    constructor(protected _store: Record<string, TAoothUserCredentials> = {}) {
        super()
    }

    exists(username: string) {
        return Promise.resolve(!!this._store[username])
    }

    async read(username: string): Promise<TAoothUserCredentials> {
        if (await this.exists(username)) {
            return deepClone(this._store[username])
        }
        throw new Error('Not found')
    }

    async loginSucceeded(username: string, date: number) {
        if (await this.exists(username)) {
            this._store[username].account.lastLogin = date
            return
        }
        throw new Error('Not found')
    }

    async loginFalied(username: string) {
        if (await this.exists(username)) {
            this._store[username].account.failedLoginAttempts++
            return
        }
        throw new Error('Not found')
    }

    async change(username: string, changes: TCumulativeChanges) {
        if (await this.exists(username)) {
            for (const [key, values] of Object.entries(changes)) {
                const data = this._store[username]
                setValue(data, key, values.value, values.op)
            }
            return
        }
        throw new Error('Not found')
    }

    async updatePasswordHistory(username: string, history: TAoothUserCredentials['password']['history']) {
        if (await this.exists(username)) {
            this._store[username].password.history = history
        }
        throw new Error('Not found')
    }

    async create(data: TAoothUserCredentials) {
        if (await this.exists(data.username)) {
            throw new Error(`User with id "${ data.username }" already exists.`)
        }
        this._store[data.username] = data
    }
}
