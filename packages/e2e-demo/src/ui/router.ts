import { createMemoryHistory, createRouter as _createRouter, createWebHistory } from "vue-router";
import ConnectedAccountsPage from "./pages/ConnectedAccountsPage.vue";
import HomePage from "./pages/HomePage.vue";
import OAuthCallbackPage from "./pages/OAuthCallbackPage.vue";
import WfPage from "./pages/WfPage.vue";

// Pretty-URL → wfid map. The workflow library's default redirect targets
// (`/login`, `/recover`, `/signup`) are bare paths because they assume a
// consumer with dedicated pages per workflow; this SPA serves every
// workflow through /wf?id=<id> so each pretty URL becomes a redirect that
// carries the query string (e.g. `?username=`) through to the workflow page.
//
// Every key in this map is a real default emitted by an @aooth/auth-moost
// workflow — see test/ui-routes.spec.ts which asserts they all resolve.
export const WORKFLOW_URL_REDIRECTS: Readonly<Record<string, string>> = {
  "/login": "auth/login/flow",
  "/recover": "auth/recovery/flow",
  "/signup": "auth/signup/flow",
  // `/accept-invite?wfs=…` is the URL emitted by the demo's `buildMagicLinkUrl`
  // for the `invite.magicLink` outlet (see aooth.ts). Mapping it to
  // `auth/invite/start` lets WfPage pick up the `wfs` query as `initialToken`
  // and resume the paused workflow inside the same SPA.
  "/accept-invite": "auth/invite/start",
};

export function createRouter() {
  const redirectRoutes = Object.entries(WORKFLOW_URL_REDIRECTS).map(([path, wfid]) => ({
    path,
    redirect: (to: { query: Record<string, unknown> }) => ({
      path: "/wf",
      query: { ...to.query, id: wfid },
    }),
  }));
  return _createRouter({
    history: import.meta.env.SSR ? createMemoryHistory() : createWebHistory(),
    routes: [
      { path: "/", name: "home", component: HomePage },
      { path: "/wf", name: "wf", component: WfPage },
      // Authenticated self-service surface — lists the signed-in user's linked
      // provider identities (GET /auth/oauth/identities) and unlinks them. The
      // only non-/wf authenticated page; reads the stashed Bearer like WfPage.
      { path: "/accounts", name: "connected-accounts", component: ConnectedAccountsPage },
      // Federated-login callback bridge — the provider's `redirect_uri` lands
      // here (a SPA route; the backend OAuthController has no GET `:provider/
      // callback`, so it falls through to the SPA). Forwards `code`/`state` into
      // the `auth/login/flow` trigger (federated login is merged into login).
      // See OAuthCallbackPage.
      {
        path: "/auth/oauth/:provider/callback",
        name: "oauth-callback",
        component: OAuthCallbackPage,
      },
      ...redirectRoutes,
    ],
  });
}
