import arbacPlugin from "@aooth/arbac-moost/plugin";
import { defineConfig } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import wfPlugin from "@atscript/moost-wf/plugin";
import ts from "@atscript/typescript";
import uiPlugin from "@atscript/ui/plugin";

export default defineConfig({
  rootDir: "src",
  plugins: [
    ts(),
    // Generated model manifest: every @db.table/@db.view export, grouped by
    // space — consumed by db.ts (syncAppSchema) so new models can't be
    // forgotten from the sync list.
    dbPlugin({ manifest: "models.gen.ts" }),
    wfPlugin(),
    uiPlugin(),
    arbacPlugin(),
  ],
  format: "dts",
  unknownAnnotation: "warn",
});
