import { TCumulativeChanges, TAoothUserCredentials } from '../types'

export abstract class UsersStore {
    public abstract exists(username: string): Promise<boolean>

    public abstract read(username: string): Promise<TAoothUserCredentials>

    public abstract change(username: string, changes: TCumulativeChanges): Promise<void>

    public abstract create(data: TAoothUserCredentials): Promise<void>
}
