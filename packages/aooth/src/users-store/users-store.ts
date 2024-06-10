import { TCumulativeChanges, TAoothUserCredentials } from '../types'

export abstract class UsersStore<T extends object = {id: string}> {
    public abstract exists(username: string): Promise<boolean>

    public abstract read(username: string): Promise<TAoothUserCredentials & T>

    public abstract change(username: string, changes: TCumulativeChanges): Promise<void>

    public abstract create(data: TAoothUserCredentials & T): Promise<void>
}
