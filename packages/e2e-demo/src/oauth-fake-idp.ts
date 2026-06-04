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

/**
 * Test-only fake identity provider HTTP endpoint (mounted ONLY under
 * `DEMO_MODE=test`, like the `__test` mailbox). It stands in for a real OAuth
 * provider's authorization endpoint: the browser is 302'd here when the login
 * form's `sso` action runs (`AuthWorkflow.beginSso`), and it immediately bounces
 * back to the signed `redirect_uri` with a freshly-minted `code` (or an `error`
 * to simulate user denial). The matching profile is registered on the shared
 * {@link FakeIdentityProvider} so the server-side `sso-callback` resolves the
 * `code` offline — no network, no real Google.
 *
 * Query knobs (all optional, sensible defaults) let a spec drive scenarios
 * without re-seeding: `sub` / `email` / `email_verified` shape the profile;
 * `deny=1` simulates the user declining consent.
 */
export function createFakeIdpController(
  provider: FakeIdentityProvider,
): new (...args: never[]) => unknown {
  // One-shot profile override for the NEXT authorize bounce. The login form
  // builds the authorize URL server-side (`AuthWorkflow.beginSso`), so a spec
  // can't thread `sub`/`email` knobs through the browser redirect — it POSTs
  // them here first instead. Consumed (cleared) by the next `authorize` so it
  // can't bleed into a later test. Drives the `needs-link` interactive path: a
  // verified profile whose email collides with an existing seeded account.
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
      // Consume the one-shot override (if any) — overrides query, which overrides
      // the default. Cleared regardless of path so a set-but-unused override
      // never leaks into the next bounce.
      const override = nextProfile;
      nextProfile = null;
      const back = new URL(redirectUri);
      back.searchParams.set("state", state);

      if (deny) {
        back.searchParams.set("error", "access_denied");
        res.status = 302;
        res.setHeader("Location", back.toString());
        return "";
      }

      // Register the profile this `code` will resolve to, then hand the code
      // back through the redirect — exactly what a real provider's
      // authorize→callback bounce does.
      const code = randomUUID();
      provider.setProfile(code, {
        subject: override?.sub ?? sub ?? "google-sub-demo",
        email: override?.email ?? email ?? "oauth.user@acme.test",
        emailVerified: override?.emailVerified ?? emailVerified !== "false",
        displayName: "OAuth Demo User",
        raw: {},
      });
      back.searchParams.set("code", code);
      res.status = 302;
      res.setHeader("Location", back.toString());
      return "";
    }
  }
  return FakeIdpController;
}
