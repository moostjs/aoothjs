import { getArbacMate } from "@aoothjs/arbac-moost";
import { Resolve } from "moost";

import { useAuth } from "./auth.composables";
import { getAuthMate } from "./auth.mate";

/**
 * Marks a route or controller as fully public — opts out of BOTH
 * authentication (auth-moost's bearer guard) AND authorization
 * (arbac-moost's `arbacAuthorizeInterceptor`).
 *
 * `authGuardInterceptor` still runs on `@Public()` handlers — it populates the
 * AuthContext when a valid credential is presented, but does NOT throw when
 * the token is missing or invalid (the handler runs with a `null` AuthContext).
 * The ARBAC interceptor short-circuits entirely via its `isPublic` check.
 *
 * Method-level decoration overrides class-level.
 */
export const Public = (): ClassDecorator & MethodDecorator => {
  const auth = getAuthMate().decorate("authPublic", true);
  const arbac = getArbacMate().decorate("arbacPublic", true);
  return ((target, key, descriptor) => {
    auth(target, key, descriptor);
    arbac(target, key, descriptor);
  }) as ClassDecorator & MethodDecorator;
};

/**
 * Resolves the authenticated user's id (string) for a handler parameter.
 *
 * Delegates to `useAuth().getUserId()`, which throws `HttpError(401)` when no
 * `AuthContext` is present in the event. There is no `@User()` counterpart —
 * `AuthContext` is credential context, not user profile data, and this library
 * does not own a user profile type.
 */
export const UserId = () => Resolve(() => useAuth().getUserId());
