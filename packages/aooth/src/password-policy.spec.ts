import { ppHasLowerCase, ppHasMinLength, ppHasNumber, ppHasSpecialChar, ppHasUpperCase, ppMaxRepeatedChars } from './password-policies'
import { PasswordPolicy } from './password-policy'

describe('password-policy', () => {
    it('must check real fn', async () => {
        const p = new PasswordPolicy({ rule: v => v.length > 5 })
        expect(await p.evaluate('12345')).toBe(false)
        expect(await p.evaluate('123456')).toBe(true)
    })

    it('must evaluate fn from string', async () => {
        const p = new PasswordPolicy({ rule: 'v.length > 5' })
        expect(await p.evaluate('12345')).toBe(false)
        expect(await p.evaluate('123456')).toBe(true)
    })

    it('must check ppHasMinLength', async () => {
        const p = new PasswordPolicy(ppHasMinLength(5))
        expect(await p.evaluate('1234')).toBe(false)
        expect(await p.evaluate('12345')).toBe(true)
    })

    it('must check ppHasUpperCase', async () => {
        const p = new PasswordPolicy(ppHasUpperCase(2))
        expect(await p.evaluate('password')).toBe(false)
        expect(await p.evaluate('Password')).toBe(false)
        expect(await p.evaluate('PassworD')).toBe(true)
        expect(await p.evaluate('PASSWORD')).toBe(true)
    })

    it('must check ppHasLowerCase', async () => {
        const p = new PasswordPolicy(ppHasLowerCase(2))
        expect(await p.evaluate('PASSWORd')).toBe(false)
        expect(await p.evaluate('PASSWORD')).toBe(false)
        expect(await p.evaluate('PASSWOrd')).toBe(true)
        expect(await p.evaluate('password')).toBe(true)
        expect(await p.evaluate('Password')).toBe(true)
        expect(await p.evaluate('PassworD')).toBe(true)
    })

    it('must check ppHasNumber', async () => {
        const p = new PasswordPolicy(ppHasNumber(2))
        expect(await p.evaluate('abcd')).toBe(false)
        expect(await p.evaluate('abcd1')).toBe(false)
        expect(await p.evaluate('1abcd1')).toBe(true)
        expect(await p.evaluate('12345')).toBe(true)
    })

    it('must check ppHasSpecialChar', async () => {
        const p = new PasswordPolicy(ppHasSpecialChar(2))
        expect(await p.evaluate('password')).toBe(false)
        expect(await p.evaluate('password!')).toBe(false)
        expect(await p.evaluate('pass!word!')).toBe(true)
    })

    it('must check ppMaxRepeatedChars', async () => {
        const p = new PasswordPolicy(ppMaxRepeatedChars(2))
        expect(await p.evaluate('aaa')).toBe(false)
        expect(await p.evaluate('abab')).toBe(true)
        expect(await p.evaluate('password!!')).toBe(true)
        expect(await p.evaluate('password!!!')).toBe(false)
    })
})
