// Demo-local pending-authorization row. Inherits every column from the shipped
// `AoothPendingAuthorization` via `extends` — same pattern as `DemoAuthCredential
// extends AoothAuthCredential` — so the demo's authorization-server schema stays
// in lockstep with `@aooth/auth`. `PendingAuthorizationStoreAtscriptDb` matches
// it structurally (by-shape table surface). The table name + depth are declared
// here so this model owns its own `@db.table` registration.
import { AoothPendingAuthorization } from '@aooth/auth/atscript-db/pending-authorization'

@db.table 'aooth_pending_authorizations'
@db.depth.limit 0
export interface DemoPendingAuthorization extends AoothPendingAuthorization {}
