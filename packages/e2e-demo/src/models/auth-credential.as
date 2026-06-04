// Demo-local credential row model. Inherits every column from the shipped
// `AoothAuthCredential` via `extends` — same pattern as
// `DemoUser extends AoothArbacUserCredentials` — so the demo's schema stays in
// lockstep with `@aooth/auth` instead of being hand-mirrored field-for-field.
// asc (rootDir: src) compiles it and `DbSpace.getTable(DemoAuthCredential)`
// returns a runtime table; `CredentialStoreAtscriptDb` matches it structurally
// (its `AuthCredentialTable` surface is by-shape), so the demo authenticates
// against a real, enumerable store — which is what makes the "active sessions"
// panel (listSessions / revokeSession / revokeOtherSessions) work end-to-end.
// The table name + depth are declared here (not inherited) so this model owns
// its own `@db.table` registration, exactly like `DemoUser`.
import { AoothAuthCredential } from '@aooth/auth/atscript-db/model'

@db.table 'aooth_credentials'
@db.depth.limit 0
export interface DemoAuthCredential extends AoothAuthCredential {
    // Restrict-only ARBAC attenuation as TYPED ROOT columns (the replacement
    // for the dropped free-form `claims.arbac` namespace). A down-scoped
    // PAT/session sets these; a normal token leaves them unset (full authority).
    // `@aooth/arbac-moost`'s `extractAttenuation` walks these annotations.

    /** Assumed-role SUBSET — intersected with the user's roles (fail-closed). */
    @arbac.attenuate.role
    @db.json
    assumedRoles?: string[]

    /** Narrow the user's `tenantId` attribute (name-decoupled from the column). */
    @arbac.attenuate.attr "tenantId"
    scopedTenant?: string

    /** Narrow the user's `departmentId` attribute. */
    @arbac.attenuate.attr "departmentId"
    scopedDepartment?: string
}
