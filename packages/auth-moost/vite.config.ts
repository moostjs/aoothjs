import atscriptRolldown from "unplugin-atscript/rolldown";
import atscriptVite from "unplugin-atscript/vite";
import { defineConfig } from "vite-plus";

// The config object is cast to sidestep a TS2321 "excessive stack depth" blow-up
// in `vp check`: vite-plus's `PackUserConfig` is a self-referential augmentation
// of its own `UserConfig`, so under cross-project linking (a duplicated vite-plus
// peer resolution in the pnpm store, which also duplicates the `Plugin` type)
// tsc exceeds its instantiation-depth limit comparing this literal against
// `UserConfig`. The cast is RESOLUTION-INDEPENDENT — it holds no matter how many
// vite-plus copies the store ends up with, unlike a dep pin (which doesn't
// survive a re-install). See CLAUDE.md → "vp check shows vite.config.ts TS2321".
const config = {
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
};

// oxlint-disable-next-line typescript/no-explicit-any -- depth-limit workaround, see above
export default defineConfig(config as any);
