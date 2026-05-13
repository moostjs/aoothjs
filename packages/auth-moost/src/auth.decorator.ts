import { getAuthMate } from "./auth.mate";

/**
 * Marks a route or controller as not requiring authentication.
 *
 * `authGuardInterceptor` still runs on `@Public()` handlers — it populates the
 * AuthContext when a valid credential is presented, but does NOT throw when
 * the token is missing or invalid (the handler runs with a `null` AuthContext).
 *
 * Method-level decoration overrides class-level.
 */
export const Public = (): ClassDecorator & MethodDecorator =>
  getAuthMate().decorate("authPublic", true);
