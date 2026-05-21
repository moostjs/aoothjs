import { createMemoryHistory, createRouter as _createRouter, createWebHistory } from "vue-router";
import HomePage from "./pages/HomePage.vue";
import WfPage from "./pages/WfPage.vue";

export function createRouter() {
  return _createRouter({
    history: import.meta.env.SSR ? createMemoryHistory() : createWebHistory(),
    routes: [
      { path: "/", name: "home", component: HomePage },
      { path: "/wf", name: "wf", component: WfPage },
      // LoginWorkflow.alternateCredentials.recoveryUrl defaults to "/recover".
      // Bridge it to our single workflow page so the forgotPassword redirect
      // lands somewhere live without forking the server-side default.
      {
        path: "/recover",
        redirect: (to) => ({ path: "/wf", query: { ...to.query, id: "auth.recovery" } }),
      },
    ],
  });
}
