import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vite-plus/test";

/**
 * Every `.as` file the `@aooth/*` packages publish (their `files` lists) is
 * compiled in the consumer's project, so each of its imports — including the
 * ones its doc comments tell consumers to copy — must resolve there: a
 * relative import to a file next to it, an `@aooth/*` import through the
 * target package's `exports` map to a file that package publishes. Toolchains
 * without a bundler plugin resolve `.as` imports through `exports` only, so a
 * missing bare key (e.g. `./atscript-db/model` next to `./atscript-db/model.as`)
 * breaks them.
 */

interface Manifest {
  name: string;
  private?: boolean;
  files?: string[];
  exports?: Record<string, string | { types?: string; default?: string }>;
}

const packagesDir = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const packages = readdirSync(packagesDir).flatMap((dir) => {
  const file = join(packagesDir, dir, "package.json");
  if (!existsSync(file)) return [];
  return [{ dir: join(packagesDir, dir), pkg: JSON.parse(readFileSync(file, "utf8")) as Manifest }];
});
const byName = new Map(packages.map((p) => [p.pkg.name, p]));

const IMPORT_RE = /import\s*\{[^}]*\}\s*from\s*['"]([^'"]+)['"]/g;

const imports = packages
  .filter((p) => !p.pkg.private)
  .flatMap((p) =>
    (p.pkg.files ?? [])
      .filter((f) => f.endsWith(".as"))
      .flatMap((f) => {
        const file = join(p.dir, f);
        const source = readFileSync(file, "utf8");
        return [...source.matchAll(IMPORT_RE)].map((m) => ({
          from: relative(packagesDir, file),
          file,
          spec: m[1],
        }));
      }),
  );

/** Whether `file` is in its package's published `files`. */
function isPublished(pkg: { dir: string; pkg: Manifest }, file: string): boolean {
  const rel = relative(pkg.dir, file);
  return (pkg.pkg.files ?? []).some((f) => rel === f || rel.startsWith(`${f}/`));
}

/** The published file an import resolves to, or a reason it does not. */
function resolveImport(file: string, spec: string): { file: string } | { error: string } {
  if (spec.startsWith(".")) {
    const base = resolve(dirname(file), spec);
    const found = [base, `${base}.as`].find((f) => existsSync(f) && f.endsWith(".as"));
    return found ? { file: found } : { error: `no ${spec}(.as) next to the importing file` };
  }
  const m = /^(@aooth\/[^/]+)(\/.*)?$/.exec(spec);
  if (!m) return { error: "not an @aooth/* or relative import" };
  const target = byName.get(m[1]);
  if (!target) return { error: `no workspace package ${m[1]}` };
  const key = `.${m[2] ?? ""}`;
  const entry = target.pkg.exports?.[key];
  const rel = typeof entry === "string" ? entry : entry?.default;
  if (rel === undefined) return { error: `${m[1]} has no "${key}" key in its exports map` };
  const resolved = join(target.dir, rel);
  if (!existsSync(resolved)) return { error: `"${key}" points at a missing file (${rel})` };
  if (!isPublished(target, resolved)) return { error: `"${key}" points at an unpublished file` };
  const types = typeof entry === "object" ? entry.types : undefined;
  if (types !== undefined && !existsSync(join(target.dir, types))) {
    return { error: `"${key}" types point at a missing file (${types})` };
  }
  return { file: resolved };
}

describe("published .as files: every import resolves through the exports map", () => {
  it("finds the cross-package imports it guards", () => {
    expect(imports.some((i) => i.spec.startsWith("@aooth/"))).toBe(true);
  });

  it.each(imports.map((i) => [i.from, i.spec, i.file] as const))(
    "%s imports '%s'",
    (_from, spec, file) => {
      const result = resolveImport(file, spec);
      expect("error" in result ? result.error : "ok").toBe("ok");
    },
  );
});
