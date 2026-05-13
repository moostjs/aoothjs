import type { AuthContext } from "@aoothjs/auth";
import type { EventContext } from "@wooksjs/event-core";
import { defineWook, key } from "@wooksjs/event-core";
import { HttpError } from "@wooksjs/event-http";

// `null` means the guard ran on a `@Public()` route with no valid credential.
// Absent means the guard never ran.
const authContextKey = key<AuthContext | null>("auth.context");

export interface AuthBindings {
  getCurrentUser<TClaims extends object = Record<string, unknown>>(): AuthContext<TClaims> | null;
  /** @throws `HttpError(401)` if no `AuthContext` is present in the event. */
  getCurrentUserId(): string;
  isAuthenticated(): boolean;
}

/**
 * Composable for accessing the current event's auth state.
 *
 * `defineWook` memoizes the bindings object per event so multiple calls share
 * one closure. Reads from the slot populated by `authGuardInterceptor`.
 */
export const useAuth = defineWook((ctx: EventContext): AuthBindings => {
  const getCurrentUser = <
    TClaims extends object = Record<string, unknown>,
  >(): AuthContext<TClaims> | null => {
    if (!ctx.has(authContextKey)) return null;
    return ctx.get(authContextKey) as AuthContext<TClaims> | null;
  };

  const getCurrentUserId = (): string => {
    const user = getCurrentUser();
    if (!user) throw new HttpError(401, "Not authenticated");
    return user.userId;
  };

  const isAuthenticated = (): boolean => getCurrentUser() !== null;

  return { getCurrentUser, getCurrentUserId, isAuthenticated };
});

/** Internal: only `authGuardInterceptor` writes the slot. */
export function setAuthContext<TClaims extends object>(
  ctx: EventContext,
  value: AuthContext<TClaims> | null,
): void {
  ctx.set(authContextKey, value as AuthContext | null);
}
