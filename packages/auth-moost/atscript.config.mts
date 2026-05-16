import { defineConfig } from "@atscript/core";
import wfPlugin from "@atscript/moost-wf/plugin";
import ts from "@atscript/typescript";
import uiPlugin from "@atscript/ui/plugin";

export default defineConfig({
  rootDir: "src",
  plugins: [ts(), wfPlugin(), uiPlugin()],
  format: "dts",
  unknownAnnotation: "warn",
});
