// Generate .as.d.ts + .as.js for this package's `.as` form models. Drives
// @atscript/core's build() directly to sidestep the moost/wooks version
// collision that breaks the `asc` CLI inside this monorepo.
//
// Mirrors `packages/arbac-moost/scripts/gen-as.mjs`.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { build } from "@atscript/core";
import { tsPlugin as ts } from "@atscript/typescript";
import uiPlugin from "@atscript/ui/plugin";

const wd = path.join(process.cwd(), "src");
const repo = await build({
  rootDir: wd,
  include: ["**/*.as"],
  plugins: [ts(), uiPlugin()],
});
const out = [
  ...(await repo.generate({ outDir: ".", format: "dts" })),
  ...(await repo.generate({ outDir: ".", format: "js" })),
];
for (const file of out) {
  if (existsSync(file.target) && readFileSync(file.target).toString() === file.content) continue;
  console.log("writing", file.target);
  writeFileSync(file.target, file.content);
}
