/**
 * Explicit string DI tokens for the ABSTRACT authorization-server stores
 * ({@link import("@aooth/auth/authz").PendingAuthorizationStore},
 * {@link import("@aooth/auth/authz").AuthCodeStore}) — the framework-agnostic
 * abstracts live in `@aooth/auth/authz`; these moost-DI binding strings stay in
 * the integration layer (the same split as `FEDERATED_IDENTITY_STORE_TOKEN`).
 *
 * Both are abstract classes. moost's constructor injection keys the
 * provide-registry by the design:paramtype class reference — fine for a CONCRETE
 * provided class, but for an abstract paramtype infact falls back to auto-
 * instantiating the body-less abstract class, yielding an object whose methods
 * are missing. Binding under an explicit string token + `@Inject(<token>)`
 * sidesteps the class-reference path (the same pattern as
 * `FEDERATED_IDENTITY_STORE_TOKEN`).
 *
 * Consumers provide the concrete instance under the exact string:
 *
 * ```ts
 * createProvideRegistry(
 *   [PENDING_AUTHORIZATION_STORE_TOKEN, () => new PendingAuthorizationStoreMemory()],
 *   [AUTH_CODE_STORE_TOKEN, () => new AuthCodeStoreMemory()],
 * )
 * ```
 */
export const PENDING_AUTHORIZATION_STORE_TOKEN = "aooth:PendingAuthorizationStore";
export const AUTH_CODE_STORE_TOKEN = "aooth:AuthCodeStore";

/**
 * DI token for the {@link import("@aooth/auth/authz").ClientRedirectPolicy} — an
 * interface, so it has no class reference to inject by. Provide the concrete
 * policy (e.g. `new LoopbackClientPolicy()`, a `RegisteredClientPolicy`, or a
 * `CompositeClientPolicy` of both) under this string.
 */
export const CLIENT_REDIRECT_POLICY_TOKEN = "aooth:ClientRedirectPolicy";

// NOTE: the Tier-2 OIDC `id_token` signer + claims resolver are NOT DI tokens —
// they are optional, and an optional `@Inject`/`@Optional` dependency panics in
// moost's `resolveMoost` route-table pass (`useHandlerPaths`). They are supplied
// instead by overriding `AuthorizeController.getIdTokenSigner()` /
// `getOidcClaimsResolver()` in a subclass (see that controller).
