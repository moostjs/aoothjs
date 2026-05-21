import { buildApp } from "./app";

async function main(): Promise<void> {
  const handle = await buildApp({ port: Number(process.env.PORT ?? 3001) });
  if (process.env.SEED !== "false") {
    // Goes through `handle.reseed()` (truncates → seedAll) so the dev-entry
    // seed and the `__test/reset` reset path share one implementation.
    await handle.reseed();
  }
  // biome-ignore lint/suspicious/noConsole: dev entry-point
  console.log(`e2e-demo running at ${handle.baseUrl}`);
}

main().catch((err) => {
  // biome-ignore lint/suspicious/noConsole: dev entry-point
  console.error(err);
  process.exit(1);
});
