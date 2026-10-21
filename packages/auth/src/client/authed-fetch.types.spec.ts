import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vite-plus/test";

// F53: in a browser project (strict + DOM lib) the wrapper must be typed as the
// real `fetch` — `.json()` on the response, `Headers` / `RequestInit` accepted,
// and `window.fetch` accepted as `options.fetch`.
const entry = fileURLToPath(new URL("./index.ts", import.meta.url)).replace(/\.ts$/, "");

const consumer = `
import { createAuthedFetch } from ${JSON.stringify(entry)};
const api = createAuthedFetch({ refreshPath: "/auth/refresh" });
export async function load(signal: AbortSignal): Promise<unknown> {
  const r = await api("/api/me", { headers: new Headers(), method: "GET", signal });
  return r.json();
}
export const custom = createAuthedFetch({ fetch: window.fetch });
export async function viaCustom(): Promise<string> {
  return (await custom(new URL("https://example.test/x"))).text();
}
`;

// A runtime with neither the DOM lib nor @types/node: only `URL` is declared.
const noDomConsumer = `
declare global { interface URL { href: string } }
import { createAuthedFetch } from ${JSON.stringify(entry)};
const api = createAuthedFetch();
export const r = api("/api/me", {
  method: "GET",
  headers: { accept: "application/json" },
  cache: "no-store",
  mode: "cors",
  redirect: "follow",
  keepalive: true,
});
`;

function diagnosticsFor(source: string, lib = ["lib.es2023.d.ts", "lib.dom.d.ts"]): string[] {
  const file = fileURLToPath(new URL("./__dom-consumer__.ts", import.meta.url));
  const options: ts.CompilerOptions = {
    strict: true,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.Preserve,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    lib,
    types: [],
  };
  const host = ts.createCompilerHost(options);
  const readFile = host.readFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  host.readFile = (name) => (name === file ? source : readFile(name));
  host.fileExists = (name) => name === file || fileExists(name);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (name, lang) =>
    name === file ? ts.createSourceFile(name, source, lang) : getSourceFile(name, lang);
  const program = ts.createProgram([file], options, host);
  return ts
    .getPreEmitDiagnostics(program)
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
}

describe("createAuthedFetch typing under the DOM lib", () => {
  it("returns the ambient fetch type and accepts DOM request/fetch types", () => {
    expect(diagnosticsFor(consumer)).toEqual([]);
  }, 30_000);

  it("accepts the standard RequestInit keys without the DOM lib", () => {
    expect(diagnosticsFor(noDomConsumer, ["lib.es2023.d.ts"])).toEqual([]);
  }, 30_000);
});
