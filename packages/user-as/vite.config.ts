import atscriptRolldown from "unplugin-atscript/rolldown";
import atscriptVite from "unplugin-atscript/vite";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [atscriptVite()],
  pack: {
    dts: true,
    format: ["esm", "cjs"],
    plugins: [atscriptRolldown()],
  },
});
