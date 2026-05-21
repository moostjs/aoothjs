import "@unocss/reset/tailwind.css";
import "virtual:uno.css";
import { installDynamicResolver } from "@atscript/ui-fns";
import { createApp } from "./app";

// Client-only: compile `@ui.form.fn.*` string expressions at runtime. Must run
// BEFORE any form is created so cached endpoint metadata / form definitions
// use the dynamic resolver from first render. Kept out of SSR (entry-server.ts
// + app.ts) because (1) workflow forms hydrate browser-side only via
// `useHydrated()`, and (2) the dynamic resolver compiles strings via
// `new Function(...)` which is server-side waste.
installDynamicResolver();

const { app, router } = createApp();
void router.isReady().then(() => app.mount("#app"));
