import { TAoothUserCredentials, TPasswordConfig, TPasswordPolicy, TPasswordPolicyEvalFn } from './types'
import { FtringsPool } from '@prostojs/ftring'

const fnPool = new FtringsPool<boolean, { v: string, password?: TAoothUserCredentials['password'], config?: TPasswordConfig }>()

export class PasswordPolicy {
    constructor(protected config: TPasswordPolicy) {}

    protected _evalFn!: TPasswordPolicyEvalFn

    evaluate(...args: Parameters<TPasswordPolicyEvalFn>): boolean | Promise<boolean> {
        if (!this._evalFn) {
            if (typeof this.config.rule === 'function') {
                this._evalFn = this.config.rule
            } else if (typeof this.config.rule === 'string' && this.config.rule) {
                const fn = fnPool.getFn(this.config.rule)
                this._evalFn = (v, password, config) => fn({ v, password, config })
            } else {
                this._evalFn = () => true
            }
        }
        return this._evalFn(...args)
    }

    get transferable() {
        return typeof this.config.rule === 'string'
    }

    get rule() {
        if (!this.transferable) throw new Error('Password Policy rule is not transferable')
        return this.config.rule as string
    }

    get description(): string {
        return this.config.description || ''
    }

    get errorMessage(): string {
        return this.config.errorMessage || ''
    }
}
