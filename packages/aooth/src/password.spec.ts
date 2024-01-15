import { Password } from './password'
import { TAoothConfig } from './types'

const algorithm = 'sha3-224'
const config: Required<Required<TAoothConfig>['password']> = {
    algorithm: algorithm,
    expiryDays: 0,
    historyLength: 5,
    pepper: 'peppervalue',
    policies: [],
    resetTokenExpiryHours: 0,
    saltGenerator: () => 'new-salt',
}

function newPassword() {
    return new Password(config, {
        algorithm: 'sha224',
        hash: '',
        history: [],
        isInitial: false,
        lastChanged: 0,
        salt: 'predefined-salt',
    })
}

describe('password', () => {
    it('must generate password', () => {
        const p = newPassword()
        p.generate()
        const data = p.getData()
        expect(data.hash).toMatch(/^[A-Za-z0-9]{8,}$/)
        expect(data.isInitial).toEqual(true)
        expect(new Date().getTime() - data.lastChanged).toBeLessThan(100)
        expect(data.salt).toEqual('predefined-salt')
        expect(data.algorithm).toEqual('sha3-224')
    })
    it('must store history', () => {
        const p = newPassword()
        p.change('password1')
        const h1 = p.getData().hash
        p.change('password2')
        const h2 = p.getData().hash
        p.change('password3')
        const data = p.getData()
        expect(data.history).toHaveLength(2)
        expect(data.history[0].hash).toEqual(h2)
        expect(data.history[1].hash).toEqual(h1)
    })
    it('must check passwords history', () => {
        let p = newPassword()
        p.change('password1')
        p = new Password({ ...config, algorithm: 'md5' }, p.getData())
        p.change('password2')
        p = new Password({ ...config, algorithm: 'sha3-512' }, p.getData())
        p.change('password3')
        p = new Password(config, p.getData())
        p.change('password4')
        expect(p.isInHistory('password1')).toBe(true)
        expect(p.isInHistory('password2')).toBe(true)
        expect(p.isInHistory('password3')).toBe(true)
        expect(p.isInHistory('password4')).toBe(false)
        const data = p.getData()
        expect(data.history[0].algorithm).toEqual('sha3-512')
        expect(data.history[1].algorithm).toEqual('md5')
        expect(data.history[2].algorithm).toEqual(algorithm)
    })
    it('must keep history length', () => {
        const p = newPassword()
        p.change('password1')
        p.change('password2')
        p.change('password3')
        p.change('password4')
        p.change('password5')
        p.change('password6')
        p.change('password7')
        const data = p.getData()
        expect(data.history).toHaveLength(5)
        expect(p.isInHistory('password1')).toBe(false)
        expect(p.isInHistory('password2')).toBe(true)
    })
    it('must validate password', () => {
        const p = newPassword()
        p.change('password1')
        expect(p.validate('password1')).toBe(true)
        expect(p.validate('password2')).toBe(false)
    })
})
