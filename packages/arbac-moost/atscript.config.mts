import { defineConfig } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import ts from "@atscript/typescript";
import arbacPlugin from "./src/plugin";

export default defineConfig({
  rootDir: "src",
  plugins: [ts(), dbPlugin(), arbacPlugin()],
  format: "dts",
  unknownAnnotation: "warn",
});
