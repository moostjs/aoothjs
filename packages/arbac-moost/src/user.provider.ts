import type { TClassConstructor } from "moost";

import type { AoothArbacClaims } from "./attenuation";

/**
 * Abstract base class for providing user data required for ARBAC evaluations.
 *
 * Consumers must extend this class and implement the three abstract methods
 * to plug their own authentication/identity layer into the ARBAC authorize
 * interceptor. The subclass must re-apply `@Injectable()` (moost does not
 * inherit decorator metadata) and be registered via Moost's
 * `setReplaceRegistry` (or `@Replace`) so DI resolves the concrete provider.
 *
 * @template TUserAttrs - The type representing user attributes relevant to access control.
 */
export abstract class ArbacUserProvider<TUserAttrs extends object = object> {
  /**
   * Retrieves the unique identifier of the current user.
   */
  abstract getUserId(): string | Promise<string>;

  /**
   * Retrieves the roles assigned to a user based on their ID.
   *
   * @param id - The user ID.
   */
  abstract getRoles(id: string): string[] | Promise<string[]>;

  /**
   * Retrieves the attributes associated with a user based on their ID.
   *
   * @param id - The user ID.
   */
  abstract getAttrs(id: string): TUserAttrs | Promise<TUserAttrs>;

  /**
   * OPTIONAL: source the credential's restrict-only ARBAC attenuation for the
   * current request. When it returns claims, `useArbac().evaluate()` runs the
   * engine's dual-pass outcome-intersection so the credential can do/see/affect
   * strictly LESS than its owning user; returning `undefined` (the default —
   * this method is unimplemented on the base/atscript providers) means "no
   * narrowing", i.e. the credential authorizes with the user's full authority.
   *
   * `arbac-moost` is auth-agnostic, so the base class does NOT read the auth
   * layer. A consumer wires it up by overriding this to read the credential's
   * typed root fields and return their attenuation — typically
   * `extractAttenuation(CredentialModel, useAuth().getAuthContext())`, which
   * walks the model's `@arbac.attenuate.*`-annotated fields (from
   * `@aooth/arbac-moost/atscript`). The restrict-only intersection happens in
   * the engine regardless, so an app cannot get the safety wrong here.
   */
  getAttenuation?(): AoothArbacClaims | undefined | Promise<AoothArbacClaims | undefined>;
}

/**
 * DI token form of {@link ArbacUserProvider}. The class itself is `abstract`,
 * so it does not satisfy moost's `TClassConstructor` (`new (...) => T`)
 * structurally; this re-typed alias is the supported way to pass the base
 * class to `cc.instantiate(...)`, `createReplaceRegistry(...)`, `@Replace(...)`,
 * etc. Runtime resolves to the concrete subclass registered via DI.
 */
export const ArbacUserProviderToken =
  ArbacUserProvider as unknown as TClassConstructor<ArbacUserProvider>;
