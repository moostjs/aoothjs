import { Aooth } from './aooth'
import { ppHasLowerCase, ppHasMinLength, ppHasNumber, ppHasSpecialChar, ppHasUpperCase, ppMaxRepeatedChars, ppNoRepeatedPasswords } from './password-policies'
import { PasswordPolicy } from './password-policy'
import { UsersStoreMemory } from './users-store'

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

    it('must check ppNoRepeatedPasswords', async () => {
        const aooth = new Aooth(new UsersStoreMemory(), {
            password: { historyLength: 20 },
        })
        const user = await aooth.createUser('test')
        const pc = aooth.getConfig().password
        user.changePassword(pc, 'test1', 'test1')
        await user.save()
        user.changePassword(pc, 'test2', 'test2')
        await user.save()
        user.changePassword(pc, 'test3', 'test3')
        await user.save()
        user.changePassword(pc, 'test4', 'test4')
        await user.save()
        user.changePassword(pc, 'test5', 'test5')
        await user.save()
        user.changePassword(pc, 'test6', 'test6')
        await user.save()
        console.log(user.getData().password)
        const p = new PasswordPolicy(ppNoRepeatedPasswords(3))
        expect(await p.evaluate('aaa', user.getData().password)).toBe(true)
        expect(await p.evaluate('test1', user.getData().password)).toBe(true)
        expect(await p.evaluate('test2', user.getData().password)).toBe(true)
        expect(await p.evaluate('test3', user.getData().password)).toBe(true)
        expect(await p.evaluate('test4', user.getData().password)).toBe(false)
        expect(await p.evaluate('test5', user.getData().password)).toBe(false)
        expect(await p.evaluate('test6', user.getData().password)).toBe(false)
    })
})
