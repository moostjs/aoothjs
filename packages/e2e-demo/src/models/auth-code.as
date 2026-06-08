// Demo-local authorization-code row. Inherits every column from the shipped
// `AoothAuthCode` via `extends` (same pattern as `DemoPendingAuthorization`), so
// the demo's schema stays in lockstep with `@aooth/auth`. `AuthCodeStoreAtscriptDb`
// matches it structurally. The table name + depth are declared here so this model
// owns its own `@db.table` registration.
import { AoothAuthCode } from '@aooth/auth/atscript-db/auth-code'

@db.table 'aooth_auth_codes'
@db.depth.limit 0
export interface DemoAuthCode extends AoothAuthCode {}
