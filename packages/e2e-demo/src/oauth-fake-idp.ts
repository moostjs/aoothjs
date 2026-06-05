import { randomUUID } from "node:crypto";
import type { FakeIdentityProvider } from "@aooth/idp";
import { Public } from "@aooth/auth-moost";
import { Body, Get, Post, Query } from "@moostjs/event-http";
import { current } from "@wooksjs/event-core";
import { useResponse } from "@wooksjs/event-http";
import { Controller } from "moost";

/** One-shot profile override settable by a spec via `POST /__fake-idp/profile`. */
interface FakeIdpProfileOverride {
  sub?: string;
  email?: string;
  emailVerified?: boolean;
}

/** Pull the `<provider>` segment out of a `/auth/oauth/:provider/callback` redirect_uri. */
function providerFromRedirectUri(redirectUri: string): string | null {
  try {
    const seg = new URL(redirectUri).pathname.split("/");
    // ['', 'auth', 'oauth', '<provider>', 'callback']
    if (seg[1] === "auth" && seg[2] === "oauth" && seg[4] === "callback") return seg[3] ?? null;
  } catch {
    /* not a URL */
  }
  return null;
}

/** Default verified email per fake provider (Google keeps its historical value). */
function defaultEmailFor(providerId: string): string {
  return providerId === "google" ? "oauth.user@acme.test" : `${providerId}.user@acme.test`;
}

/** Minimal HTML escape for the auto-submit form_post values. */
function esc(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** An auto-submitting POST form — stands in for Apple's `response_mode=form_post`. */
function autoSubmitForm(action: string, fields: Record<string, string>): string {
  const inputs = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join("");
  return `<!doctype html><html><body onload="document.forms[0].submit()"><form method="post" action="${esc(
    action,
  )}">${inputs}</form></body></html>`;
}

/**
 * Test-only fake identity provider HTTP endpoint (mounted ONLY under
 * `DEMO_MODE=test`, like the `__test` mailbox). It stands in for a real OAuth
 * provider's authorization endpoint: the browser is 302'd here when the login
 * form's `sso` action runs (`AuthWorkflow.beginSso`), and it bounces back to the
 * signed `redirect_uri` with a freshly-minted `code` (or an `error` to simulate
 * user denial). The matching profile is registered on the right
 * {@link FakeIdentityProvider} (resolved from the redirect_uri's `:provider`
 * segment) so the server-side `sso-callback` resolves the `code` offline.
 *
 * Two callback transports, matching the real providers:
 * - default (Google / GitHub): a **302 GET** back to `redirect_uri?code&state`.
 * - `mode=form_post` (Apple): an auto-submitting **POST** form to `redirect_uri`
 *   — exercising the `OAuthController` POST→GET bounce.
 *
 * Query knobs (all optional): `sub` / `email` / `email_verified` shape the
 * profile; `deny=1` simulates the user declining consent.
 */
export function createFakeIdpController(
  providers: FakeIdentityProvider[],
): new (...args: never[]) => unknown {
  const byId = new Map(providers.map((p) => [p.id, p]));

  // One-shot profile override for the NEXT authorize bounce (any provider). The
  // login form builds the authorize URL server-side (`AuthWorkflow.beginSso`), so
  // a spec can't thread `sub`/`email` knobs through the browser redirect — it
  // POSTs them here first instead. Consumed (cleared) by the next `authorize`.
  let nextProfile: FakeIdpProfileOverride | null = null;

  @Controller("__fake-idp")
  class FakeIdpController {
    @Post("profile")
    @Public()
    setNextProfile(@Body() body: FakeIdpProfileOverride): { ok: true } {
      nextProfile = { ...body };
      return { ok: true };
    }

    @Get("authorize")
    @Public()
    authorize(
      @Query("redirect_uri") redirectUri: string | undefined,
      @Query("state") state: string | undefined,
      @Query("mode") mode: string | undefined,
      @Query("sub") sub: string | undefined,
      @Query("email") email: string | undefined,
      @Query("email_verified") emailVerified: string | undefined,
      @Query("deny") deny: string | undefined,
    ): string {
      const res = useResponse(current());
      if (!redirectUri || !state) {
        res.status = 400;
        return "fake-idp: missing redirect_uri or state";
      }
      const providerId = providerFromRedirectUri(redirectUri);
      const provider = providerId ? byId.get(providerId) : undefined;
      if (!provider) {
        res.status = 400;
        return `fake-idp: no fake provider for redirect_uri '${redirectUri}'`;
      }
      // Consume the one-shot override (if any). Cleared regardless of path so a
      // set-but-unused override never leaks into the next bounce.
      const override = nextProfile;
      nextProfile = null;

      // The two transports converge on the SAME params back to redirect_uri.
      const isFormPost = mode === "form_post";

      if (deny) {
        return this.bounce(res, redirectUri, isFormPost, { state, error: "access_denied" });
      }

      // Register the profile this `code` resolves to, then hand the code back.
      const code = randomUUID();
      provider.setProfile(code, {
        subject: override?.sub ?? sub ?? `${provider.id}-sub-demo`,
        email: override?.email ?? email ?? defaultEmailFor(provider.id),
        emailVerified: override?.emailVerified ?? emailVerified !== "false",
        displayName: "OAuth Demo User",
        raw: {},
      });
      return this.bounce(res, redirectUri, isFormPost, { state, code });
    }

    /** GET 302 (default) or an auto-submitting POST form (`form_post`) back to redirect_uri. */
    private bounce(
      res: ReturnType<typeof useResponse>,
      redirectUri: string,
      isFormPost: boolean,
      fields: { state: string; code?: string; error?: string },
    ): string {
      const flat: Record<string, string> = { state: fields.state };
      if (fields.code) flat.code = fields.code;
      if (fields.error) flat.error = fields.error;

      if (isFormPost) {
        res.status = 200;
        res.setHeader("content-type", "text/html; charset=utf-8");
        return autoSubmitForm(redirectUri, flat);
      }
      const back = new URL(redirectUri);
      for (const [k, v] of Object.entries(flat)) back.searchParams.set(k, v);
      res.status = 302;
      res.setHeader("Location", back.toString());
      return "";
    }
  }
  return FakeIdpController;
}
