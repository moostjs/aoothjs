import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
      redis: "src/redis/index.ts",
      "atscript-db": "src/atscript-db/index.ts",
    },
    dts: true,
    format: ["esm", "cjs"],
  },
});
