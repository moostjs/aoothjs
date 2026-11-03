import atscriptVite from "unplugin-atscript/vite";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [atscriptVite()],
  pack: {
    deps: {
      // tsdown <0.23 compatibility: resolve external dependency subpaths.
      // Remove to preserve subpath imports as written (the new default).
      // https://tsdown.dev/options/dependencies#deps-resolvedepsubpath
      resolveDepSubpath: true,
    },
    entry: {
      index: "src/index.ts",
      redis: "src/redis/index.ts",
      "atscript-db": "src/atscript-db/index.ts",
      client: "src/client/index.ts",
      authz: "src/authz/index.ts",
    },
    dts: true,
    format: ["esm", "cjs"],
  },
});
