// Cookieless demo: the bundled login finish returns `data.accessToken`. The SPA
// stashes it in sessionStorage and replays it as `Authorization: Bearer` for the
// guarded triggers (change-password) and the self-scoped connected-accounts
// routes — the demo is otherwise cookieless (see DemoAuthWorkflow.resolveRedirect).
// One source for the key + read/write so WfPage / OAuthCallbackPage /
// ConnectedAccountsPage stay in sync.
export const DEMO_TOKEN_KEY = "aooth_demo_access_token";

export function readDemoToken(): string | null {
  return typeof sessionStorage === "undefined" ? null : sessionStorage.getItem(DEMO_TOKEN_KEY);
}

export function writeDemoToken(token: string): void {
  if (typeof sessionStorage !== "undefined") sessionStorage.setItem(DEMO_TOKEN_KEY, token);
}
