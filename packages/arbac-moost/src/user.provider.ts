import { Injectable } from "moost";

/**
 * Base class for providing user data required for ARBAC evaluations.
 *
 * Consumers must extend this class and implement the three abstract-style
 * methods to plug their own authentication/identity layer into the ARBAC
 * authorize interceptor. Replace the abstract instance via Moost's
 * `setReplaceRegistry` (or `@Replace`) so DI resolves the concrete provider.
 *
 * @template TUserAttrs - The type representing user attributes relevant to access control.
 */
@Injectable()
export class ArbacUserProvider<TUserAttrs extends object = object> {
  /**
   * Retrieves the unique identifier of the current user.
   *
   * @returns The user ID, or a rejected promise if not implemented.
   */
  getUserId(): string | Promise<string> {
    return Promise.reject(new Error("ArbacUserProvider class must be extended"));
  }

  /**
   * Retrieves the roles assigned to a user based on their ID.
   *
   * @param id - The user ID.
   * @returns Role identifiers, or a rejected promise if not implemented.
   */
  getRoles(id: string): string[] | Promise<string[]> {
    void id;
    return Promise.reject(new Error("ArbacUserProvider class must be extended"));
  }

  /**
   * Retrieves the attributes associated with a user based on their ID.
   *
   * @param id - The user ID.
   * @returns User attributes, or a rejected promise if not implemented.
   */
  getAttrs(id: string): TUserAttrs | Promise<TUserAttrs> {
    void id;
    return Promise.reject(new Error("ArbacUserProvider class must be extended"));
  }
}
