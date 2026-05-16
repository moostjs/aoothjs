import { getArbacMate } from "@aoothjs/arbac-moost";

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
