import { AnnotationSpec, defineConfig } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import ts from "@atscript/typescript";
import arbacPlugin from "./src/plugin";

export default defineConfig({
  rootDir: "src",
  plugins: [ts(), dbPlugin(), arbacPlugin()],
  format: "dts",
  unknownAnnotation: "warn",
  // Stand-in for atscript-ui's `@ui.valueHelp` (a dictionary binding): the
  // overlay prunes the key by name, and arbac-moost does not import the ui plugin.
  annotations: {
    ui: {
      valueHelp: new AnnotationSpec({
        argument: [
          { name: "target", type: "ref" },
          { name: "field", type: "string" },
          { name: "filter", type: "query", optional: true },
        ],
      }),
    },
  },
});
