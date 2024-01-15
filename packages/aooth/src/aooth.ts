import { generateMfaCode, generateTOTPSecretKey } from './crypto'
import { Password } from './password'
import { PasswordPolicy } from './password-policy'
import { TAoothConfig } from './types'
import { UserCredentials } from './user-credentials'
import { UsersStore } from './users-store/users-store'

export class Aooth {
    protected config: {
        password: Required<Required<TAoothConfig>['password']>
        lockout: Required<Required<TAoothConfig>['lockout']>
        mfa: Required<Required<TAoothConfig>['mfa']>
    }

    constructor(protected store: UsersStore, config?: TAoothConfig) {
        const policies = []
        for (const policy of config?.password?.policies || []) {
            if (policy instanceof PasswordPolicy) {
                policies.push(policy)
            } else {
                policies.push(new PasswordPolicy(policy))
            }
        }

        this.config = Object.freeze({
            password: {
                algorithm: config?.password?.algorithm || 'sha3-224',
                expiryDays: config?.password?.expiryDays || 0,
                historyLength: config?.password?.historyLength || 0,
                pepper: config?.password?.pepper || '',
                resetTokenExpiryHours: config?.password?.resetTokenExpiryHours || 1,
                saltGenerator: config?.password?.saltGenerator || (() => generateTOTPSecretKey(5)),
                policies,
            },
            lockout: {
                threshold: config?.lockout?.threshold || 0,
                duration: config?.lockout?.duration || 0,
            },
            mfa: {
                required: config?.mfa?.required || false,
                length: config?.mfa?.length || 6,
            },
        })
    }

    getConfig() {
        return this.config
    }

    user(username: string) {
        return new UserCredentials(this.store, username)
    }

    password() {
        const pwConfig = this.config.password
        return new Password(pwConfig)
    }

    getPasswordPolicies(): PasswordPolicy[] {
        return this.config.password.policies as PasswordPolicy[]
    }

    getTransferablePasswordPolicies(): {
        rule: string
        description?: string
        errorMessage?: string
    }[] {
        return (this.config.password.policies as PasswordPolicy[]).filter(p => p.transferable).map(p => ({
            rule: p.rule,
            description: p.description,
            errorMessage: p.errorMessage,
        }))
    }

    async createUser(username: string) {
        const user = new UserCredentials(this.store, username)
        await user.create(this.config.password)
        return user
    }

    async isUserLocked(username: string, unlockWhenEnded?: boolean) {
        const user = this.user(username)
        await user.read()
        return user.isLocked(unlockWhenEnded)
    }

    async getUserData(username: string) {
        const user = this.user(username)
        await user.read()
        return user.getData()
    }

    async validatePassword(username: string, password: string, bypassEffect = false) {
        const user = this.user(username)
        await user.read()
        const success = user.validatePassword(this.config.password, password)
        if (!bypassEffect) {
            if (success) {
                user.loginSucceeded()
            } else {
                const fla = user.getData().account.failedLoginAttempts + 1
                user.loginFailed()
                if (this.config.lockout.threshold && fla >= this.config.lockout.threshold) {
                    user.lockAccount('Too many login attempts', this.config.lockout.duration ? new Date().getTime() + this.config.lockout.duration : 0)
                }
            }
            await user.save()
        }
        return success
    }

    genMfaCode() {
        return generateMfaCode(this.config.mfa.length)
    }
}
