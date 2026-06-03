import { FederatedLoginService, OAuthProviderRegistry } from "@aooth/idp";
import { Inject, Injectable } from "moost";

import { OAuthFlowStore } from "./oauth-flow-store";
import { OAUTH_FLOW_STORE_TOKEN } from "./oauth-tokens";

/**
 * DI holder bundling the three app-provided federated-login singletons the
 * `oauth-exchange` workflow step needs. It exists so the step can resolve them
 * via `getMoostInfact().get(OAuthRuntime)`: a DIRECT `.get(token)` of a
 * factory-provided / abstract class fails (infact tries to auto-instantiate
 * it), but `.get` of THIS `@Injectable` class instantiates it and resolves its
 * constructor deps THROUGH the provide-registry — the same path that injects
 * `AuthCredential` & friends elsewhere.
 *
 * The app provides `OAuthProviderRegistry`, `FederatedLoginService`, and a
 * concrete `OAuthFlowStore` via `createProvideRegistry`; this class wires them
 * together for the step without touching `AuthWorkflow`'s constructor (so the
 * documented subclass ctor signature stays unchanged).
 */
@Injectable()
export class OAuthRuntime {
  constructor(
    readonly registry: OAuthProviderRegistry,
    readonly federated: FederatedLoginService,
    // Abstract — inject via the string token (see oauth-tokens.ts for why a
    // class-reference token can't resolve an abstract provided store).
    @Inject(OAUTH_FLOW_STORE_TOKEN) readonly flowStore: OAuthFlowStore,
  ) {}
}
