import type { EventContext } from "@wooksjs/event-core";
import { useAuthorization, useCookies } from "@wooksjs/event-http";

import type { MoostAuthConfig } from "./auth.config";

/**
 * Extracts the access token from the current request using the same rules as
 * `authGuardInterceptor`: `Authorization: Bearer ...` wins over cookie when
 * both transports are enabled.
 */
export function extractAccessToken(ctx: EventContext, config: MoostAuthConfig): string | undefined {
  let token: string | undefined;
  if (config.enableBearer) {
    const auth = useAuthorization(ctx);
    if (auth.is("bearer")) token = auth.credentials() ?? undefined;
  }
  if (!token && config.enableCookie) {
    token = useCookies(ctx).getCookie(config.cookie.name) ?? undefined;
  }
  return token;
}
