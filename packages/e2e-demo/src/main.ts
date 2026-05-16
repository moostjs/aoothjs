import { buildApp } from "./app";
import { seedAll } from "./seed";

async function main(): Promise<void> {
  const handle = await buildApp({ port: Number(process.env.PORT ?? 3001) });
  if (process.env.SEED !== "false") {
    await seedAll(handle);
  }
  // biome-ignore lint/suspicious/noConsole: dev entry-point
  console.log(`e2e-demo running at ${handle.baseUrl}`);
}

main().catch((err) => {
  // biome-ignore lint/suspicious/noConsole: dev entry-point
  console.error(err);
  process.exit(1);
});
