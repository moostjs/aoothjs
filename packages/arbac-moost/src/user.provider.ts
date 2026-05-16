import type { TClassConstructor } from "moost";

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
