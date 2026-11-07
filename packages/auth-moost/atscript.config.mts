import { defineConfig } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import wfPlugin from "@atscript/moost-wf/plugin";
import ts from "@atscript/typescript";
import uiPlugin from "@atscript/ui/plugin";
import uiFnsPlugin from "@atscript/ui-fns/plugin";

export default defineConfig({
  rootDir: "src",
  // `dbPlugin` under vitest only — for the specs that run the shipped
  // `@aooth/user` model on a real SQLite table. Kept out of `vp pack` / `asc`,
  // whose output it would change (it registers the `@db.*` annotations).
  plugins: [
    ts(),
    ...(process.env.VITEST ? [dbPlugin()] : []),
    wfPlugin(),
    uiPlugin(),
    uiFnsPlugin(),
  ],
  format: "dts",
  unknownAnnotation: "warn",
});
