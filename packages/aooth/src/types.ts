import { PasswordPolicy } from './password-policy'

export interface TAoothUserCredentials {
    id: string
    username: string // User's username (used for login)
    password: {
        hash: string
        salt: string
        algorithm: TCryptoAlgorithm
        history: { algorithm: TCryptoAlgorithm, hash: string }[]
        lastChanged: number
        isInitial: boolean
    }
    account: {
        active: boolean
        locked: boolean
        lockReason: string
        lockEnds: number
        failedLoginAttempts: number
        lastLogin: number
    }
    mfa: {
        email: {
            address: string
            confirmed: boolean
        },
        sms: {
            confirmed: boolean
            number: string
        },
        totp: {
            secretKey: string
        },
        default: '' | 'sms' | 'email' | 'totp'
        autoSend: boolean
    }
}

export type TCryptoAlgorithm = 'md5' | 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512'

export type TPasswordPolicyEvalFn = ((v: string, password?: TAoothUserCredentials['password'], config?: TPasswordConfig) => (boolean | Promise<boolean>))

export interface TPasswordPolicy {
    rule: string | TPasswordPolicyEvalFn
    description?: string
    errorMessage?: string
}

export type TChangeOperation = 'set' | 'unset' | 'inc'

export type TCumulativeChanges = Record<string, { oldValue: unknown, value: unknown, op: TChangeOperation }>

export interface TPasswordConfig { algorithm: TCryptoAlgorithm, pepper?: string, historyLength?: number, policies?: (TPasswordPolicy | PasswordPolicy)[] }

export interface TAoothConfig {
    password?: {
        expiryDays?: number
        resetTokenExpiryHours?: number
        saltGenerator?: () => string
    } & Partial<TPasswordConfig>

    lockout?: {
        threshold?: number
        duration?: number
    }

    mfa?: {
        required?: boolean
        length?: number
    }
}

export interface TAuthWorkflowState {
    code: string
    title?: string
    prompt?: string
    info?: string
    inputs: TAuthInputMetadata[]
}

export interface TAuthInputMetadata {
    name: string
    label: string
    type: 'string' | 'password' | 'email' | 'phone' | 'pin' | 'action'
    action?: string
    url?: string
    length?: number
    required?: boolean
}

export interface TAuthWorkflow {
    id: string
    steps: {
        start: { test: boolean }
    }
}

