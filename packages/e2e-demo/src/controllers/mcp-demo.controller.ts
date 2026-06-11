import type { AuthCredential } from "@aooth/auth";
import {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  buildWwwAuthenticateBearerChallenge,
  type AuthorizationServerMetadata,
  type ProtectedResourceMetadata,
  Public,
} from "@aooth/auth-moost";
import { Get, Post } from "@moostjs/event-http";
import { current } from "@wooksjs/event-core";
import { useHeaders, useResponse } from "@wooksjs/event-http";
import { Controller } from "moost";

export interface McpDemoControllerOptions {
  /** The authorization-server issuer — `{origin}/auth`, byte-exact. */
  issuer: string;
  /** The protected resource identifier — the canonical `/mcp` URL. */
  resource: string;
  /** Scopes the resource understands (advertised in both documents). */
  scopes: string[];
  /** Validates the presented bearer token. */
  auth: AuthCredential;
}

/**
 * The OAUTH.md acceptance proof for the ROOT-mounted pieces a prefix-mounted
 * `AuthorizeController` cannot register itself, built from the EXPORTED
 * builders (R1/R3):
 *
 * - `GET /.well-known/oauth-authorization-server/auth` — the RFC 8414
 *   path-insertion form for the `/auth` issuer path. Byte-identical payload to
 *   the controller-mounted suffix form (same builder, same issuer).
 * - `GET /.well-known/oauth-protected-resource` — the RFC 9728 PRM pointing
 *   connector clients at the issuer.
 * - `GET|POST /mcp` — a stand-in for a real MCP endpoint: 401s with the
 *   RFC 9728 §5.1 `WWW-Authenticate: Bearer resource_metadata="…"` challenge
 *   until a valid bearer token is presented (this header is what kicks off the
 *   whole connector discovery flow).
 */
export function makeMcpDemoController(
  opts: McpDemoControllerOptions,
): new (...args: never[]) => unknown {
  const prmUrl = `${new URL(opts.issuer).origin}/.well-known/oauth-protected-resource`;

  @Controller()
  class McpDemoController {
    @Get(".well-known/oauth-authorization-server/auth")
    @Public()
    pathInsertionMetadata(): AuthorizationServerMetadata {
      return buildAuthorizationServerMetadata({
        issuer: opts.issuer,
        registrationEndpoint: `${opts.issuer}/register`,
        jwksUri: `${opts.issuer}/jwks`,
        scopesSupported: opts.scopes,
      });
    }

    @Get(".well-known/oauth-protected-resource")
    @Public()
    protectedResourceMetadata(): ProtectedResourceMetadata {
      return buildProtectedResourceMetadata({
        resource: opts.resource,
        authorizationServers: [opts.issuer],
        scopesSupported: opts.scopes,
        resourceName: "Demo MCP resource",
      });
    }

    @Get("mcp")
    @Public()
    mcpGet(): Promise<unknown> {
      return this.handleMcp();
    }

    @Post("mcp")
    @Public()
    mcpPost(): Promise<unknown> {
      return this.handleMcp();
    }

    /**
     * Bearer-or-challenge: a missing/invalid token answers 401 with the PRM
     * challenge header (never a redirect — MCP clients are not browsers); a
     * valid token answers a small JSON proof.
     */
    private async handleMcp(): Promise<unknown> {
      const res = useResponse(current());
      const authorization = useHeaders(current()).authorization ?? "";
      const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : undefined;
      const ctx = token ? await opts.auth.validate(token) : null;
      if (!ctx) {
        res.status = 401;
        res.setHeader(
          "WWW-Authenticate",
          buildWwwAuthenticateBearerChallenge({
            resourceMetadataUrl: prmUrl,
            ...(token !== undefined && { error: "invalid_token" }),
          }),
        );
        return { error: "unauthorized" };
      }
      res.status = 200; // a body-returning POST otherwise defaults to 201
      return { ok: true, userId: ctx.userId };
    }
  }

  return McpDemoController as new (...args: never[]) => unknown;
}
