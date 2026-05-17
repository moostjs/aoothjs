import atscriptRolldown from "unplugin-atscript/rolldown";
import atscriptVite from "unplugin-atscript/vite";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [atscriptVite()],
  pack: {
    entry: {
      index: "src/index.ts",
      "atscript/index": "src/atscript/index.ts",
    },
    dts: true,
    // ESM-only for the atscript sub-export — it re-exports atscript-
    // generated classes and vite-plus does not propagate user plugins into
    // the cjs-dts emit pass. Mirrors the pattern in `@atscript/moost-wf`
    // and `@aooth/arbac-moost`.
    format: ["esm"],
    plugins: [atscriptRolldown()],
    deps: {
      neverBundle: [
        "@aooth/auth",
        "@aooth/user",
        "@atscript/moost-wf",
        "@atscript/typescript",
        "moost",
        "@moostjs/event-wf",
        "@wooksjs/event-core",
        "@wooksjs/event-http",
      ],
    },
  },
});
