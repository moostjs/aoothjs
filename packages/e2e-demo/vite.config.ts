import atscriptVite from "unplugin-atscript/vite";
import vue from "@vitejs/plugin-vue";
import { moostVite } from "@moostjs/vite";
import unocss from "@unocss/vite";
import { defineConfig } from "vite-plus";

// Vitest also evaluates this config and runs every plugin's `configureServer`.
// moost-vite's configureServer imports `/src/main.ts`, which calls `buildApp`
// (binds the HTTP port, opens the SQLite db) — fine in dev, fatal in tests
// because the harness calls buildApp itself. Skip moost-vite under vitest.
// Playwright gets the same escape hatch (PLAYWRIGHT=1) — defensive, in case
// a future playwright run ever evaluates this file directly.
const isVitest = !!process.env.VITEST;
const isPlaywright = process.env.PLAYWRIGHT === "1";
const skipMoostVite = isVitest || isPlaywright;

export default defineConfig({
  server: { port: 3001 },
  // Vitest picks up any *.spec.ts under the package by default. Playwright
  // specs live in `test-e2e/` and use `@playwright/test`'s incompatible
  // `test()` runner — exclude them from `vp test` (vitest) so they only run
  // under `pnpm test:e2e`.
  test: {
    exclude: ["test-e2e/**", "node_modules/**", "dist/**"],
    // This package's tests are Playwright (`test-e2e/`, run via `pnpm test:e2e`);
    // it ships no vitest specs, so a recursive `vp test` must not fail it.
    passWithNoTests: true,
  },
  // Dev-only: bundle packages that ship raw `.as` source so unplugin-atscript
  // can transform them.
  ssr: {
    noExternal: [/^@aooth\//, /^@atscript\//, /^vunor($|\/)/],
  },
  plugins: [
    atscriptVite(),
    unocss(),
    vue(),
    // No `prefix` — the existing backend mounts controllers at root-level
    // paths (e.g. `@Controller("auth")` → `/auth/...`). Letting moost-vite
    // forward every unmatched request to Moost preserves those paths for the
    // e2e tests which keep importing `buildApp` from `src/app.ts` directly.
    ...(skipMoostVite
      ? []
      : [
          moostVite({
            entry: "/src/main.ts",
            middleware: true,
            ssrEntry: "/src/ui/entry-server.ts",
          }),
        ]),
  ],
});
