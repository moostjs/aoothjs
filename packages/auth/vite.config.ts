import atscriptVite from "unplugin-atscript/vite";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [atscriptVite()],
  pack: {
    entry: {
      index: "src/index.ts",
      redis: "src/redis/index.ts",
      "atscript-db": "src/atscript-db/index.ts",
      client: "src/client/index.ts",
    },
    dts: true,
    format: ["esm", "cjs"],
  },
});
