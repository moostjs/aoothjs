import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

import { allowTableRead, defineRole } from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import type { BaseDbAdapter } from "@atscript/db";
import type { MoostHttp } from "@moostjs/event-http";

/*
 * Test utilities shared by the HTTP-level specs. NOT exported from the
 * package's public entry — internal use only.
 */

/** A response as the specs read it: status, parsed JSON body (else the text), raw text. */
export interface TestResponse {
  status: number;
  body: any;
  text: string;
}

/** `http.request` with an optional JSON body; the body is parsed as JSON when it is. */
export async function request(
  http: MoostHttp,
  method: string,
  path: string,
  body?: unknown,
): Promise<TestResponse> {
  const res = await http.request(path, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res!.text();
  let parsed: unknown = text;
  try {
    parsed = JSON.parse(text);
  } catch {
    // keep text
  }
  return { status: res!.status, body: parsed, text };
}

/** A role granting `allowTableRead(resource)` per entry — the given scope, `undefined` = unscoped. */
export function readerRole<TScope extends object>(
  id: string,
  grants: Record<string, TScope | undefined>,
): TArbacRole<object, TScope> {
  let b = defineRole<object, TScope>().id(id);
  for (const [resource, scope] of Object.entries(grants)) {
    b = b.use(allowTableRead<object, TScope>(resource, scope ? { scope: () => scope } : undefined));
  }
  return b.build();
}

/**
 * `@atscript/db-memory` as `@atscript/moost-db` resolves it — the ESM entry,
 * so it shares the test's `@atscript/db` instance (not a devDependency of
 * this package).
 */
export async function loadMemoryAdapter(): Promise<new () => BaseDbAdapter> {
  const req = createRequire(import.meta.url);
  const moostDb = req.resolve("@atscript/moost-db/package.json");
  const pkgPath = createRequire(moostDb).resolve("@atscript/db-memory/package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
    exports: { ".": { import: string } };
  };
  const entry = pathToFileURL(join(dirname(pkgPath), pkg.exports["."].import)).href;
  const mod = (await import(/* @vite-ignore */ entry)) as {
    MemoryAdapter: new () => BaseDbAdapter;
  };
  return mod.MemoryAdapter;
}
