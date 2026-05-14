import atscriptRolldown from "unplugin-atscript/rolldown";
import atscriptVite from "unplugin-atscript/vite";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [atscriptVite()],
  pack: {
    entry: {
      index: "src/index.ts",
      plugin: "src/plugin.ts",
      "atscript/index": "src/atscript/index.ts",
    },
    dts: true,
    // ESM-only for the atscript sub-export — it re-exports atscript-
    // generated classes (`AoothArbacUserCredentials`) and vite-plus
    // does not propagate user plugins into the cjs-dts emit pass.
    // Mirrors the pattern in `@atscript/moost-wf`.
    format: ["esm"],
    plugins: [atscriptRolldown()],
    deps: {
      neverBundle: [
        "@aoothjs/arbac",
        "@aoothjs/arbac-core",
        "@aoothjs/user-as",
        "@atscript/core",
        "@atscript/db",
        "@atscript/moost-db",
        "@atscript/typescript",
        "@moostjs/event-http",
        "moost",
        "@wooksjs/event-core",
        "@wooksjs/event-http",
      ],
    },
  },
});
