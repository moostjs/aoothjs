import { existsSync, readFileSync, writeFileSync } from "fs";
import path from "path";

import { build } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import { tsPlugin as ts } from "@atscript/typescript";

/**
 * Compile the `.as` fixtures in this directory to `.as.js` + `.as.d.ts` so
 * the integration spec can `import("./fixtures/auth-credential.as")` and
 * receive the runtime metadata class. Writes only when content differs to
 * keep watch-mode quiet.
 *
 * Mirrors `packages/user/src/atscript-db/__test__/test-utils.ts`.
 */
export async function prepareFixtures(): Promise<void> {
  const wd = path.join(path.dirname(import.meta.url.slice(7)), "fixtures");
  const repo = await build({
    rootDir: wd,
    include: ["**/*.as"],
    plugins: [ts(), dbPlugin()],
  });
  const out = await repo.generate({ outDir: ".", format: "js" });
  const outDts = await repo.generate({ outDir: ".", format: "dts" });
  for (const file of [...out, ...outDts]) {
    if (existsSync(file.target)) {
      const content = readFileSync(file.target).toString();
      if (content !== file.content) writeFileSync(file.target, file.content);
    } else {
      writeFileSync(file.target, file.content);
    }
  }
}
