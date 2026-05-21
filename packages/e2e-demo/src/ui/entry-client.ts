import "@unocss/reset/tailwind.css";
import "virtual:uno.css";
import { createApp } from "./app";

const { app, router } = createApp();
void router.isReady().then(() => app.mount("#app"));
