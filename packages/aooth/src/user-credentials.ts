import { Changeable } from './changeable'
import { Password } from './password'
import { TCumulativeChanges, TPasswordConfig, TAoothConfig, TAoothUserCredentials } from './types'
import { UsersStore } from './users-store/users-store'
import { getValue, setValue, unsetAll } from './utils/get-set'

const isEmail = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/

export class UserCredentials extends Changeable {
    protected data!: TAoothUserCredentials

    constructor(
        protected store: UsersStore,
        protected username: string,
        changes?: TCumulativeChanges,
    ) {
        super(changes || {})
    }

    getData() {
        return this.data
    }

    exists() {
        return this.store.exists(this.username)
    }

    create(config: TPasswordConfig & Pick<Required<Required<TAoothConfig>['password']>, 'saltGenerator'>) {
        this.data = {
            id: '',
            username: this.username,
            password: {
                algorithm: config.algorithm,
                hash: '',
                history: [],
                isInitial: false,
                lastChanged: 0,
                salt: config.saltGenerator(),
            },
            account: {
                failedLoginAttempts: 0,
                active: false,
                locked: false,
                lockEnds: 0,
                lastLogin: 0,
                lockReason: '',
            },
            mfa: {
                email: {
                    address: isEmail.exec(this.username) ? this.username : '',
                    confirmed: false,
                },
                phone: {
                    confirmed: false,
                    number: '',
                },
                totp: {
                    secretKey: '',
                },
                default: '',
                autoSend: false,
            },
        }
        const pw = this.password(config)
        pw.generate()
        this.data.password = pw.getData()
        return this.store.create(this.data)
    }

    protected _userDataQueried = false

    async read(force = false) {
        if (force || !this._userDataQueried) {
            this.data = await this.store.read(this.username)
            this._userDataQueried = true
        }
        return this.data
    }

    acitvateAccount() {
        this.pushChange('account.active', 'set', true)
    }

    deacitvateAccount() {
        this.pushChange('account.active', 'set', false)
    }

    lockAccount(reason: string, lockEnds: number) {
        this.pushChange('account.locked', 'set', true)
        this.pushChange('account.lockReason', 'set', reason)
        this.pushChange('account.lockEnds', 'set', lockEnds)
    }

    unlockAccount() {
        this.pushChange('account.locked', 'set', false)
        this.pushChange('account.lockReason', 'set', '')
        this.pushChange('account.lockEnds', 'set', 0)
    }

    password(config: TPasswordConfig) {
        return new Password(config, this.data.password, this.changes)
    }

    changePassword(config: TPasswordConfig, pw1: string, pw2: string) {
        return this.password(config).change(pw1, pw2)
    }

    validatePassword(config: TPasswordConfig, password: string) {
        return this.password(config).validate(password)
    }

    loginSucceeded() {
        this.pushChange('account.lastLogin', 'set', new Date().getTime())
        this.pushChange('account.failedLoginAttempts', 'set', 0)
    }

    loginFailed() {
        this.pushChange('account.failedLoginAttempts', 'inc', 1)
    }

    protected getCurrentValue(path: string) {
        return getValue(this.data || {}, path)
    }

    protected ensureDataExists() {
        if (!this.data) {
            this.data = { username: this.username } as TAoothUserCredentials
        }
    }

    async save() {
        await this.store.change(this.username, this.changes)
        this.ensureDataExists()
        for (const [path, values] of Object.entries(this.changes)) {
            setValue(this.data, path, values.value, values.op)
        }
        unsetAll(this.changes)
    }

    getEmailMasked() {
        const s = this.getData().mfa?.email?.address || ''
        if (s) {
            const [name, domain] = s.split('@')
            return [mask(name), domain].join('@')
        }
        return ''
    }

    getPhoneMasked() {
        const s = this.getData().mfa?.phone?.number || ''
        return mask(s)
    }

    getMfaOptions() {
        const { mfa } = this.getData()
        const options = []
        if (mfa.email.confirmed) options.push({ type: 'email', value: mfa.email.address, masked: this.getEmailMasked(), isDefault: mfa.default === 'email' })
        if (mfa.phone.confirmed) options.push({ type: 'sms', value: mfa.phone.number, masked: this.getPhoneMasked(), isDefault: mfa.default === 'sms' })
        if (mfa.totp.secretKey) options.push({ type: 'totp', value: mfa.totp.secretKey, masked: '', isDefault: mfa.default === 'totp' })
        return options
    }

    setMfaDefaultMethod(method: TAoothUserCredentials['mfa']['default']) {
        this.pushChange('mfa.default', 'set', method)
        this.pushChange('mfa.autoSend', 'set', false)
    }

    setMfaAutoSend(value = true) {
        this.pushChange('mfa.autoSend', 'set', value)
    }

    setMfaConfirmed(method: 'email' | 'sms', value = true) {
        this.pushChange(`mfa.${method}.confirmed`, 'set', value)
    }

    isLocked(unlockWhenEnded?: boolean) {
        if (unlockWhenEnded && this.getData().account.lockEnds > 0 && this.getData().account.locked && this.getData().account.lockEnds < new Date().getTime()) {
            this.unlockAccount()
            return { locked: false, reason: '', ends: 0, endsIn: ''}
        }
        const { account } = this.getData()
        return {
            locked: account.locked,
            reason: account.lockReason,
            ends: account.lockEnds,
            endsIn: account.locked ? (this.getData().account.lockEnds > 0 ? `Block is effective for ${Math.ceil((account.lockEnds - new Date().getTime()) / 1000 / 60) } more minute(s)` : '') : '',
        }
    }
}

function mask(s: string) {
    if (s) {
        return s.length > 2 ? s.slice(0, Math.floor(s.length / 4)) + '***' + s.slice(-Math.ceil(s.length / 4)) : '***'
    }
    return ''
}
