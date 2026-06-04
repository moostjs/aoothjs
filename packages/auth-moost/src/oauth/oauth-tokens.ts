/**
 * Explicit string DI token for the ABSTRACT `FederatedIdentityStore`.
 *
 * `FederatedIdentityStore` is an abstract class. moost's constructor injection
 * keys the provide-registry by the design:paramtype class reference, which
 * resolves a CONCRETE provided class fine (e.g. `AuthCredential`) but not an
 * abstract one — for an abstract paramtype infact falls back to auto-
 * instantiating the (body-less) abstract class, yielding an object whose methods
 * are missing. Binding the store under an explicit string token and injecting it
 * with `@Inject(<token>)` sidesteps the class-reference path entirely (the same
 * pattern the demo uses for its `"EmailSender"` provider).
 *
 * Consumers provide the concrete instance under this exact string:
 *
 * ```ts
 * createProvideRegistry(
 *   [FEDERATED_IDENTITY_STORE_TOKEN, () => new FederatedIdentityStoreAtscriptDb({ table })],
 * )
 * ```
 */
export const FEDERATED_IDENTITY_STORE_TOKEN = "aooth:FederatedIdentityStore";
