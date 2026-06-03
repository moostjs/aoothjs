/**
 * Explicit string DI tokens for the two ABSTRACT federated-login stores.
 *
 * `OAuthFlowStore` and `FederatedIdentityStore` are abstract classes. moost's
 * constructor injection keys the provide-registry by the design:paramtype class
 * reference, which resolves a CONCRETE provided class fine (e.g. `AuthCredential`)
 * but not an abstract one — for an abstract paramtype infact falls back to
 * auto-instantiating the (body-less) abstract class, yielding an object whose
 * methods are missing (`flowStore.put is not a function`). Binding these stores
 * under explicit string tokens and injecting them with `@Inject(<token>)`
 * sidesteps the class-reference path entirely (the same pattern the demo uses
 * for its `"EmailSender"` provider).
 *
 * Consumers provide the concrete instances under these exact strings:
 *
 * ```ts
 * createProvideRegistry(
 *   [OAUTH_FLOW_STORE_TOKEN, () => new OAuthFlowStoreMemory()],
 *   [FEDERATED_IDENTITY_STORE_TOKEN, () => new FederatedIdentityStoreAtscriptDb({ table })],
 * )
 * ```
 */
export const OAUTH_FLOW_STORE_TOKEN = "aooth:OAuthFlowStore";
export const FEDERATED_IDENTITY_STORE_TOKEN = "aooth:FederatedIdentityStore";
