import { hashPassword } from './crypto'
import { TPasswordConfig, TAoothConfig } from './types'
import { UserCredentials } from './user-credentials'
import { UsersStoreMemory } from './users-store/users-store-memory'

const persistentStore = new UsersStoreMemory()
let store: UsersStoreMemory
let user: UserCredentials
const config: TPasswordConfig & Pick<Required<Required<TAoothConfig>['password']>, 'saltGenerator'> = {
    saltGenerator: () => 'salt',
    algorithm: 'sha3-224',
}
const username = 'test@user.com'

describe('user-credentials', () => {
    beforeAll(async () => {
        await (new UserCredentials(persistentStore, 'user1@test.com')).create(config)
        await (new UserCredentials(persistentStore, 'user2@test.com')).create(config)
        await (new UserCredentials(persistentStore, 'user3@test.com')).create(config)
    })

    beforeEach(() => {
        store = new UsersStoreMemory()
        user = new UserCredentials(store, username)
    })
    it('must create user', async () => {
        await user.create(config)
        const data = user.getData()
        expect(data.username).toEqual(username)
        expect(data.account.active).toBe(false)
        expect(data.password.salt).toEqual('salt')
        expect(data.password.hash).toMatch(/^[A-Za-z0-9]+$/)
        expect(data.password.isInitial).toBe(true)
    })
    it('must change password', async () => {
        await user.create(config)
        user.changePassword(config, 'newPassword', 'newPassword')
        await user.save()
        const data = user.getData()
        expect(data.password.hash).toEqual(hashPassword('newPassword' + 'salt', config.algorithm))
        expect(data.password.history).toHaveLength(1)
    })
    it('must read user', async () => {
        const user = new UserCredentials(persistentStore, 'user1@test.com')
        await user.read()
        const data = user.getData()
        expect(data.username).toEqual('user1@test.com')
        expect(data.account.active).toBe(false)
        expect(data.password.salt).toEqual('salt')
        expect(data.password.hash).toMatch(/^[A-Za-z0-9]+$/)
        expect(data.password.isInitial).toBe(true)
    })
    it('must activate user', async () => {
        const user = new UserCredentials(persistentStore, 'user1@test.com')
        user.acitvateAccount()
        await user.save()
        const data = user.getData()
        expect(data.account.active).toBe(true)
        await user.read()
        expect(user.getData().account.active).toBe(true)
    })
    it('must (un)lock user', async () => {
        const user = new UserCredentials(persistentStore, 'user1@test.com')
        user.lockAccount('test lock', 0)
        await user.save()
        const data = user.getData()
        expect(data.account.locked).toBe(true)
        await user.read()
        expect(user.getData().account.locked).toBe(true)
        user.unlockAccount()
        await user.save()
        expect(user.getData().account.locked).toBe(false)
        await user.read()
        expect(user.getData().account.locked).toBe(false)
    })
    it('must validate password', async () => {
        let user = new UserCredentials(persistentStore, 'user1@test.com')
        await user.read()
        user.changePassword(config, 'password', 'password')
        await user.save()
        user = new UserCredentials(persistentStore, 'user1@test.com')
        await user.read()
        expect(user.validatePassword(config, 'password')).toBe(true)
    })
    it('must set lastLogin', async () => {
        const user = new UserCredentials(persistentStore, 'user1@test.com')
        await user.read()
        expect(user.getData().account.lastLogin).toBe(0)
        user.loginSucceeded()
        await user.save()
        expect(user.getData().account.lastLogin).toBeGreaterThan(0)
    })
    it('must increase failed attempts', async () => {
        const user = new UserCredentials(persistentStore, 'user1@test.com')
        await user.read()
        expect(user.getData().account.failedLoginAttempts).toBe(0)
        user.loginFailed()
        await user.save()
        expect(user.getData().account.failedLoginAttempts).toBe(1)
        user.loginFailed()
        await user.save()
        expect(user.getData().account.failedLoginAttempts).toBe(2)
    })
    it('must check users existence', async () => {
        expect(await (new UserCredentials(persistentStore, 'user1@test.com')).exists()).toBeTruthy()
        expect(await (new UserCredentials(persistentStore, 'user2@test.com')).exists()).toBeTruthy()
        expect(await (new UserCredentials(persistentStore, 'user3@test.com')).exists()).toBeTruthy()
        expect(await (new UserCredentials(persistentStore, 'unknown-user@test.com')).exists()).toBeFalsy()
    })
})
