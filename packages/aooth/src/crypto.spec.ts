import { generateTOTPSecretKey, generateMfaCode } from './crypto'

describe('crypto', () => {
    it('must generate TOTP secret key in base32 encoding', () => {
        const key = generateTOTPSecretKey()
        expect(key).toHaveLength(32)
        expect(key).toMatch(/^[A-Z2-7]{16,}$/)
    })
    it('must generate MFA code', () => {
        const code = generateMfaCode(6)
        console.log({ code })
        expect(code).toHaveLength(6)
        expect(code).toMatch(/^\d{6}$/)
    })
})
