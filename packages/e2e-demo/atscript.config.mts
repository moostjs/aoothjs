import arbacPlugin from "@aoothjs/arbac-moost/plugin";
import { defineConfig } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import wfPlugin from "@atscript/moost-wf/plugin";
import ts from "@atscript/typescript";
import uiPlugin from "@atscript/ui/plugin";

export default defineConfig({
  rootDir: "src",
  plugins: [ts(), dbPlugin(), wfPlugin(), uiPlugin(), arbacPlugin()],
  format: "dts",
  unknownAnnotation: "warn",
});
