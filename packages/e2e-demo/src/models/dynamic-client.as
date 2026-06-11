// Demo-local dynamic-client row (RFC 7591 registrations). Inherits every column
// from the shipped `AoothDynamicClient` via `extends` — same pattern as
// `DemoPendingAuthorization extends AoothPendingAuthorization` — so the demo's
// authorization-server schema stays in lockstep with `@aooth/auth`.
// `DynamicClientStoreAtscriptDb` matches it structurally (by-shape table
// surface). The table name + depth are declared here so this model owns its
// own `@db.table` registration.
import { AoothDynamicClient } from '@aooth/auth/atscript-db/dynamic-client'

@db.table 'aooth_dynamic_clients'
@db.depth.limit 0
export interface DemoDynamicClient extends AoothDynamicClient {}
