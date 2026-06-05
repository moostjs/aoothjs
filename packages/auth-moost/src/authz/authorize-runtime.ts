import type { AuthCodeStore, PendingAuthorizationStore } from "@aooth/auth/authz";
import { Inject, Injectable } from "moost";

import { AUTH_CODE_STORE_TOKEN, PENDING_AUTHORIZATION_STORE_TOKEN } from "./authz-tokens";

/**
 * DI holder bundling the two abstract authorization-server stores the login-wf
 * terminal (`mint-authz-code`) needs. A `@Step` body cannot `@Inject` a string
 * token, so it resolves THIS `@Injectable` via
 * `useControllerContext().instantiate(AuthorizeRuntime)` — instantiating it
 * resolves its constructor deps THROUGH the provide-registry (the same path that
 * injects `AuthCredential` & friends), keeping `AuthWorkflow`'s documented ctor
 * untouched. Mirrors `OAuthRuntime`.
 */
@Injectable()
export class AuthorizeRuntime {
  constructor(
    @Inject(PENDING_AUTHORIZATION_STORE_TOKEN) readonly pending: PendingAuthorizationStore,
    @Inject(AUTH_CODE_STORE_TOKEN) readonly codes: AuthCodeStore,
  ) {}
}
