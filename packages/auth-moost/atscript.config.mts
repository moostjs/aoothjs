import { defineConfig } from "@atscript/core";
import wfPlugin from "@atscript/moost-wf/plugin";
import ts from "@atscript/typescript";
import uiPlugin from "@atscript/ui/plugin";
import uiFnsPlugin from "@atscript/ui-fns/plugin";

export default defineConfig({
  rootDir: "src",
  plugins: [ts(), wfPlugin(), uiPlugin(), uiFnsPlugin()],
  format: "dts",
  unknownAnnotation: "warn",
});
