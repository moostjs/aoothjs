import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
    },
    dts: true,
    deps: {
      neverBundle: [
        "@aoothjs/auth",
        "@aoothjs/user",
        "moost",
        "@wooksjs/event-core",
        "@wooksjs/event-http",
      ],
    },
  },
});
