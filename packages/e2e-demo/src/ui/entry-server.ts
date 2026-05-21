// CSS is imported only from entry-client.ts. Vite emits one stylesheet for the
// client bundle which the SSR template references; importing CSS here would
// trip Node with "Unknown file extension .css" in prod.
import { renderToString } from "vue/server-renderer";
import { createApp } from "./app";

export async function render(url: string) {
  const { app, router } = createApp();
  await router.push(url);
  await router.isReady();

  const ctx: Record<string, unknown> = {};
  const html = await renderToString(app, ctx);
  const state = JSON.stringify(ctx.state || {});
  return { html, state };
}
