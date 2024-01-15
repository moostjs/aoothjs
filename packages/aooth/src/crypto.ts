import { randomBytes, createHash, getRandomValues } from 'crypto'
import { TCryptoAlgorithm } from './types'
import { base32 } from './base-x'

/**
 * Generates random secret string for TOTP
 * @param length default 20
 * @returns string
 */
export function generateTOTPSecretKey(length = 20) {
    return base32.encode(randomBytes(length)).toString().toUpperCase()
}

/**
 * Generates hash for salted password
 * @param value salted password
 * @param algorithm crypto algorithm
 * @returns hash
 */
export function hashPassword(value: string, algorithm: TCryptoAlgorithm) {
    const hash = createHash(algorithm)
    hash.update(value)
    return hash.digest('hex')
}

export function generateMfaCode(length = 6) {
    const randomBuffer = new Uint8Array(length)
    getRandomValues(randomBuffer)
    return Array.from(randomBuffer).map(b => (b % 10).toString()).join('')
}
