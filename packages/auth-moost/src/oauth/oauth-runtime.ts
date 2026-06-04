import { FederatedLoginService, OAuthProviderRegistry } from "@aooth/idp";
import { Injectable } from "moost";

/**
 * DI holder bundling the two app-provided federated-login singletons the
 * `sso-callback` workflow step needs. It exists so the step can resolve them
 * via `useControllerContext().instantiate(OAuthRuntime)`: instantiating THIS
 * `@Injectable` class resolves its constructor deps THROUGH the provide-registry
 * — the same path that injects `AuthCredential` & friends elsewhere.
 *
 * The app provides `OAuthProviderRegistry` + `FederatedLoginService` via
 * `createProvideRegistry`; this class wires them together for the step without
 * touching `AuthWorkflow`'s constructor (so the documented subclass ctor stays
 * unchanged). NO flow store: the PKCE verifier + OIDC nonce are derived
 * statelessly from the signed-state seed (see `OAuthProviderRegistry.deriveSeededPkce`).
 */
@Injectable()
export class OAuthRuntime {
  constructor(
    readonly registry: OAuthProviderRegistry,
    readonly federated: FederatedLoginService,
  ) {}
}
