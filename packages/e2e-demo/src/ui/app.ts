import { createSSRApp } from "vue";
import { installDynamicResolver } from "@atscript/ui-fns";
import App from "./App.vue";
import { createRouter } from "./router";

// Compile `@ui.form.fn.*` string expressions at runtime — required for the
// context-driven paragraphs (e.g. MfaCodeForm's transport hint) and dynamic
// option lists used by the auth workflows. Mutates `@atscript/ui` globals on
// import; called once, side-effect-free at module init time.
installDynamicResolver();

export function createApp() {
  const app = createSSRApp(App);
  const router = createRouter();
  app.use(router);
  return { app, router };
}
