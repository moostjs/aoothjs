#!/usr/bin/env node
// @aooth/arbac codegen CLI
//
// Generates TypeScript union types from a built array of @aooth/arbac roles.
//
// Usage:
//   aoothjs-arbac-codegen --roles <path> --output <path> [--export-name <name>]
//
// Notes:
//   * --roles must point to a JS/MJS module that node can import directly.
//     The module must export either a default export or a named `roles` export
//     containing an array of built roles (the result of `defineRole(...).build()`).
//   * If you author roles in TypeScript, build them first with your existing
//     toolchain and point --roles at the built JS output.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { argv, cwd, exit, stderr, stdout } from "node:process";
import { pathToFileURL } from "node:url";

/**
 * @typedef {{ rolesPath?: string; outputPath?: string; resourceTypeName?: string; actionTypeName?: string; help?: boolean }} TParsedArgs
 */

const HELP_TEXT = `aoothjs-arbac-codegen — generate TS resource/action union types

Usage:
  aoothjs-arbac-codegen --roles <path> --output <path> [options]

Required:
  --roles <path>            Path to a JS/MJS file that exports built roles
                            (default export, or named export \`roles\`).
  --output <path>           Path to write the generated .ts file.

Options:
  --resource-type <name>    Name of the resource union type. Default: Resource
  --action-type <name>      Name of the action union type.   Default: Action
  --export-name <name>      Alias for --resource-type (kept for compatibility).
  -h, --help                Show this help.
`;

/**
 * @param {string[]} args
 * @returns {TParsedArgs}
 */
function parseArgs(args) {
  /** @type {TParsedArgs} */
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case "-h":
      case "--help":
        out.help = true;
        break;
      case "--roles":
        out.rolesPath = args[++i];
        break;
      case "--output":
        out.outputPath = args[++i];
        break;
      case "--resource-type":
      case "--export-name":
        out.resourceTypeName = args[++i];
        break;
      case "--action-type":
        out.actionTypeName = args[++i];
        break;
      default:
        throw new Error(`Unknown argument: ${a}`);
    }
  }
  return out;
}

/**
 * Resolve a CLI path argument to an absolute path.
 * @param {string} p
 */
function toAbsolute(p) {
  return isAbsolute(p) ? p : resolve(cwd(), p);
}

/**
 * Pick the roles array from a dynamically-imported module.
 * Accepts: default export array, or named `roles` export array.
 * @param {Record<string, unknown>} mod
 * @param {string} importedFrom
 */
function pickRoles(mod, importedFrom) {
  /** @type {unknown} */
  let candidate = mod.default;
  if (!Array.isArray(candidate)) {
    candidate = mod.roles;
  }
  if (!Array.isArray(candidate)) {
    throw new Error(
      `Module at ${importedFrom} must export a default array or a named \`roles\` array of built roles.`,
    );
  }
  return /** @type {import("@aooth/arbac-core").TArbacRole<unknown, unknown>[]} */ (candidate);
}

async function loadCodegenApi() {
  // Prefer the built dist (works after `vp pack`); fall back to the source for
  // dev workflows where dist hasn't been built yet.
  try {
    return await import("../dist/index.mjs");
  } catch {
    return await import("../src/index.ts");
  }
}

async function main() {
  /** @type {TParsedArgs} */
  let parsed;
  try {
    parsed = parseArgs(argv.slice(2));
  } catch (err) {
    stderr.write(`${/** @type {Error} */ (err).message}\n\n${HELP_TEXT}`);
    exit(2);
    return;
  }

  if (parsed.help) {
    stdout.write(HELP_TEXT);
    return;
  }

  if (!parsed.rolesPath || !parsed.outputPath) {
    stderr.write(`Both --roles and --output are required.\n\n${HELP_TEXT}`);
    exit(2);
    return;
  }

  const rolesAbs = toAbsolute(parsed.rolesPath);
  const outAbs = toAbsolute(parsed.outputPath);

  const mod = await import(pathToFileURL(rolesAbs).href);
  const roles = pickRoles(/** @type {Record<string, unknown>} */ (mod), rolesAbs);

  const { extractResourceActions, generateResourceTypes } = await loadCodegenApi();
  const map = extractResourceActions(roles);
  const source = generateResourceTypes(map, {
    resourceTypeName: parsed.resourceTypeName,
    actionTypeName: parsed.actionTypeName,
  });

  await mkdir(dirname(outAbs), { recursive: true });
  await writeFile(outAbs, source, "utf8");
  stdout.write(`aoothjs-arbac-codegen: wrote ${outAbs}\n`);
}

main().catch((err) => {
  stderr.write(`aoothjs-arbac-codegen: ${err.stack || err.message || String(err)}\n`);
  exit(1);
});
