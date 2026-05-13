import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { build } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import { tsPlugin as ts } from "@atscript/typescript";

import arbacPlugin from "../../plugin";

/**
 * Compile `__test__/fixtures/*.as` to `.as.d.ts` + `.as.js`. Driven via
 * `@atscript/core`'s `build()` API rather than the `asc` CLI to avoid the
 * monorepo's wooks/moost version chain collision.
 */
export async function prepareFixtures(): Promise<void> {
  const wd = path.join(path.dirname(new URL(import.meta.url).pathname), "fixtures");
  const repo = await build({
    rootDir: wd,
    include: ["**/*.as"],
    plugins: [ts(), dbPlugin(), arbacPlugin()],
  });
  const out = [
    ...(await repo.generate({ outDir: ".", format: "dts" })),
    ...(await repo.generate({ outDir: ".", format: "js" })),
  ];
  for (const file of out) {
    if (existsSync(file.target) && readFileSync(file.target).toString() === file.content) continue;
    writeFileSync(file.target, file.content);
  }
}
