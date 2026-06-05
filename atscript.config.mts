// Workspace-root atscript config — a deliberate no-op fallback, NOT used to compile anything.
//
// Why this file exists: `unplugin-atscript`'s vite plugin (used by every package
// whose `vite.config.ts` calls `atscriptVite()`) probes for an atscript config
// EAGERLY at plugin-construction time, walking up from `process.cwd()`. When
// `vp run --filter './packages/*' <task>` (see the `ready`/`test`/`build` scripts)
// evaluates those package configs from the WORKSPACE ROOT to build its task graph,
// `process.cwd()` is the repo root — which had no atscript config in its ancestry.
// The plugin then calls the upstream `loadConfig(undefined)`, which throws
// `path.extname(undefined)` as an UNHANDLED rejection and crashes the whole `vp`
// process before any package task runs (unplugin-atscript@0.1.69 / @atscript/core@0.1.69,
// both already the latest published — the eager probe has no error handling).
//
// This root config makes that root-cwd probe resolve cleanly. It is never used to
// compile real `.as` models: there are none at the repo root, and every package
// resolves its OWN nearest `packages/<pkg>/atscript.config.mts` first (resolveConfigFile
// returns the nearest config walking up from the package dir). Keep it minimal and
// plugin-free so it pulls in no extra deps at the root. Do NOT delete it — `vp run`
// across the workspace will start crashing again.
import { defineConfig } from "@atscript/core";

export default defineConfig({
  rootDir: "src",
  format: "dts",
  unknownAnnotation: "warn",
});
