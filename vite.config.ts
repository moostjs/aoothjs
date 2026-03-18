import { defineConfig } from "vite-plus";

export default defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  fmt: {
    ignorePatterns: ["**/*.as.d.ts", "**/atscript.d.ts"],
  },
  lint: {
    ignorePatterns: ["scripts/*", "**/*.as"],
    categories: {
      correctness: "error",
      suspicious: "warn",
      perf: "warn",
      style: "off",
      pedantic: "off",
      restriction: "off",
      nursery: "off",
    },
    options: { typeAware: true, typeCheck: true },
    rules: {
      "no-explicit-any": "off",
      "no-this-alias": "warn",
      "no-empty-function": "off",
      "no-inferrable-types": "off",
      "no-implied-eval": "off",
      "no-unsafe-type-assertion": "off",
      "no-shadow": "off",
      "no-await-in-loop": "off",
    },
  },
});
