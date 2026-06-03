// Demo-local federated-identity row. Inherits every column from the shipped
// `AoothFederatedIdentity` via `extends` — same pattern as `DemoAuthCredential
// extends AoothAuthCredential` — so the demo's account-linking schema stays in
// lockstep with `@aooth/user`. `FederatedIdentityStoreAtscriptDb` matches it
// structurally (by-shape table surface). The table name + depth are declared
// here so this model owns its own `@db.table` registration.
//
// D7 note: the original plan was a hard FK (`userId → DemoUser.id` + onDelete
// cascade). atscript blocks it on two counts — overriding an inherited field
// in `extends` is disallowed, and an FK can only target a LOCALLY-declared `id`
// (`DemoUser.id` is inherited from `AoothArbacUserCredentials`, so it is not
// referenceable; this is also why `DemoAuthCredential.userId` is a plain
// string). So the demo keeps the base's portable posture: `userId` is a plain
// indexed column and GDPR / account-deletion cleanup goes through the
// app-level `FederatedIdentityStore.deleteAllForUser(userId)`.
import { AoothFederatedIdentity } from '@aooth/user/atscript-db/federated-model'

@db.table 'aooth_federated_identities'
@db.depth.limit 0
export interface DemoFederatedIdentity extends AoothFederatedIdentity {}
