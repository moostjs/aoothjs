import atscriptVite from "unplugin-atscript/vite";
import vue from "@vitejs/plugin-vue";
import { moostVite } from "@moostjs/vite";
import unocss from "@unocss/vite";
import { defineConfig } from "vite-plus";

// Vitest also evaluates this config and runs every plugin's `configureServer`.
// moost-vite's configureServer imports `/src/main.ts`, which calls `buildApp`
// (binds the HTTP port, opens the SQLite db) — fine in dev, fatal in tests
// because the harness calls buildApp itself. Skip moost-vite under vitest.
const isVitest = !!process.env.VITEST;

export default defineConfig({
  server: { port: 3001 },
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
    ...(isVitest
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
