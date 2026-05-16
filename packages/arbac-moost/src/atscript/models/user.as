import { AoothUserCredentials } from '@aoothjs/user/atscript-db/model'

/**
 * Base credential record for ARBAC-enabled atscript users.
 * Pre-applies `@arbac.role` to `roles: string[]` so subclasses inherit it.
 */
export interface AoothArbacUserCredentials extends AoothUserCredentials {
    @arbac.role
    roles: string[]
}
