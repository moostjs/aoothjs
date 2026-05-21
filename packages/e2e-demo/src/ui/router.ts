import { createMemoryHistory, createRouter as _createRouter, createWebHistory } from "vue-router";
import HomePage from "./pages/HomePage.vue";
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
  "/login": "auth.login",
  "/recover": "auth.recovery",
  "/signup": "auth.invite",
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
      ...redirectRoutes,
    ],
  });
}
