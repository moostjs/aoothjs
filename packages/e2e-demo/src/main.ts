import { buildApp } from "./app";

// vite / vite-node may re-evaluate this entry on file changes (moost-vite's
// `hotUpdate` invalidates the entry module and re-imports it on the next
// request). Without a process-wide guard, every re-eval invokes `buildApp` +
// `reseed` again — each `BetterSqlite3Driver(":memory:")` opens an isolated
// DB, so concurrent reseeds race and surface as FK violations on user
// inserts. globalThis is process-scoped, so the first main() promise is
// shared across re-imports.
/* eslint-disable no-underscore-dangle -- intentional globalThis slot */
const g = globalThis as { __aoothE2eBooted?: Promise<void> };

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

(g.__aoothE2eBooted ??= main()).catch((err) => {
  // biome-ignore lint/suspicious/noConsole: dev entry-point
  console.error(err);
  process.exit(1);
});
/* eslint-enable no-underscore-dangle */
