import { createMemoryHistory, createRouter as _createRouter, createWebHistory } from "vue-router";
import HomePage from "./pages/HomePage.vue";
import WfPage from "./pages/WfPage.vue";

export function createRouter() {
  return _createRouter({
    history: import.meta.env.SSR ? createMemoryHistory() : createWebHistory(),
    routes: [
      { path: "/", name: "home", component: HomePage },
      { path: "/wf", name: "wf", component: WfPage },
    ],
  });
}
