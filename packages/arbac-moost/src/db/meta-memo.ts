import type { TMetaResponse } from "@atscript/db";
import { stableMeta } from "@atscript/moost-db";

import { isBuiltVisibility } from "./visibility";
import type { MetaVisibility } from "./visibility";

/*
 * `/meta` projection memo (since 0.1.78).
 *
 * The ARBAC `/meta` overlay keeps evaluating the principal's grants on every
 * request (that is the correctness boundary). Only the PURE part after it —
 * pruning the cached envelope by the evaluated decisions — is memoized, keyed
 * by a DECISION RECORD: the normalized answers the pruning reads (allowed
 * actions / crud ops, per-level projection + identifiers + declared relations
 * + resolved relations, writable fields, nested writes, the `controls` gates,
 * the foreign `ref` targets' visibility). Never by the scopes' JSON: a
 * fingerprint drops symbols and functions and would collide across users.
 *
 * The encoder is fail-closed: anything it cannot key exactly (a hand-built
 * visibility, a symbol-keyed or function-valued scope piece — e.g. a
 * one-sided `INHERITED_CONJUNCTION` sub-scope —, a non-plain value) makes the
 * request skip the memo (computed as before, uncached).
 *
 * Memoized outputs go through moost-db's `stableMeta()` (deep-frozen, marked
 * identity-stable), so moost-db's later `/meta` steps (decorations, the
 * index-visibility narrowing, the own-mount path) memoize on them too and the
 * final object is sent from JSON serialized once, with a weak ETag (since
 * 0.1.81; before, those steps rebuilt it per request — no ETag, no 304).
 */

/** Deepest relation nesting the decision record follows; deeper → not memoized. */
const MAX_RECORD_DEPTH = 16;

class Unkeyable extends Error {}
const UNKEYABLE = new Unkeyable("unkeyable /meta decision");

function refuse(): never {
  throw UNKEYABLE;
}

// Stable per-process ids of identity-stable inputs (tables, types).
const ids = new WeakMap<object, number>();
let nextId = 1;

function idOf(obj: object | undefined): number {
  if (!obj) return 0;
  let id = ids.get(obj);
  if (id === undefined) ids.set(obj, (id = nextId++));
  return id;
}

/**
 * Validate a scope list without copying it: no symbol-keyed scope (the
 * `INHERITED_CONJUNCTION` marker of a one-sided `with` sub-scope) and no
 * function-valued scope piece, `with` sub-scopes recursively. Each scope
 * object is visited once per record (`seen`). The record itself keys on the
 * visibility DERIVED from the scopes (row data never reaches `/meta`).
 */
function checkScopes(scopes: readonly object[] | undefined, seen: Set<object>, depth = 0): void {
  if (!scopes) return;
  if (depth > MAX_RECORD_DEPTH) refuse();
  for (const scope of scopes) {
    if (seen.has(scope)) continue;
    if (scope === null || typeof scope !== "object") refuse();
    seen.add(scope);
    if (Object.getOwnPropertySymbols(scope).length > 0) refuse();
    const record = scope as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const value = record[key];
      if (typeof value === "function" || typeof value === "symbol") refuse();
      if (key === "with" && value !== undefined && value !== null) {
        if (typeof value !== "object" || Object.getOwnPropertySymbols(value).length > 0) refuse();
        checkScopes(Object.values(value) as object[], seen, depth + 1);
      }
    }
  }
}

/** A projection (`path` → `0 | 1`) as sorted `[path, flag, …]`; anything else refuses. */
function projectionKey(projection: object): unknown[] {
  if (Object.getOwnPropertySymbols(projection).length > 0) refuse();
  const keys = Object.keys(projection).toSorted();
  const out: unknown[] = [];
  for (const key of keys) {
    const flag = (projection as Record<string, unknown>)[key];
    if (flag !== 0 && flag !== 1) refuse();
    out.push(key, flag);
  }
  return out;
}

/** Sorted strings of a set / list; a non-string refuses. */
function sortedNames(names: Iterable<unknown>): string[] {
  const out: string[] = [];
  for (const name of names) {
    if (typeof name !== "string") refuse();
    out.push(name);
  }
  return out.toSorted();
}

/** Relation names per level, as `/meta`'s serialized type reaches them. */
export type MetaNameTree = ReadonlyMap<string, MetaNameTree>;
const NO_TREE: MetaNameTree = new Map();

/** What the record encoder needs from the overlay. */
export interface MetaRecordContext {
  /** Whether a no-field `ref` target type is table-served. */
  isServed: (type: object) => boolean;
  /** PK + `preferredId` of a table (the identifiers a built level always shows). */
  identifiers: (table: MetaVisibility["table"]) => ReadonlySet<string>;
}

/**
 * One visibility level: its table, normalized projection, parent-authority
 * relations, and every relation the pruning can resolve at this level — the
 * `/meta` relation names (`tree`, what the overlay resolved) and the declared
 * `with` names — as the child level or `null`. Only levels built by
 * `buildScopeVisibility` (whose `isAllowed` / `relation` are pure functions
 * of exactly these) are accepted.
 */
function encodeLevel(
  vis: MetaVisibility,
  tree: MetaNameTree,
  ctx: MetaRecordContext,
  seen: Set<object>,
  depth: number,
): unknown[] {
  if (depth > MAX_RECORD_DEPTH || !isBuiltVisibility(vis)) refuse();
  if (vis.alwaysVisible !== ctx.identifiers(vis.table)) refuse();
  checkScopes(vis.scopes, seen);
  const withGrants = sortedNames(vis.withGrants);
  const names =
    tree.size === 0 ? withGrants : sortedNames(new Set([...tree.keys(), ...withGrants]));
  const relations: unknown[] = [];
  for (const name of names) {
    const sub = vis.relation?.(name);
    relations.push(
      name,
      sub ? encodeLevel(sub, tree.get(name) ?? NO_TREE, ctx, seen, depth + 1) : 0,
    );
  }
  return [idOf(vis.table), projectionKey(vis.allowed), withGrants, relations];
}

/** Inputs of one `/meta` projection (see `applyArbacMetaOverlay`). */
export interface MetaDecisionInput {
  /** `meta.actions[i]` allowed, in envelope order. */
  actions: readonly boolean[];
  /** `meta.crud` op allowed, in envelope key order. */
  crud: readonly boolean[];
  readScopes: readonly object[];
  writeScopes: readonly object[];
  /** Absent when no read op is allowed (no pruning). */
  projection?: {
    vis: MetaVisibility;
    /** The relation names the overlay resolved (`resolveRelationTree`), per level. */
    tree: MetaNameTree;
    writable: ReadonlySet<string> | "all" | undefined;
    nestedWrites: ReadonlySet<string> | undefined;
    /** Keys the write scopes pin via `set`. */
    forced?: ReadonlySet<string>;
    /** Each allowed read op's effective `controls` policy (`false` / whitelist per key). */
    controls: Readonly<Partial<Record<string, Readonly<Record<string, unknown>>>>>;
    refTargets: ReadonlyMap<object, MetaVisibility | null>;
  };
}

/** Bit string of `flags`. */
function bits(flags: readonly boolean[]): string {
  let out = "";
  for (const flag of flags) out += flag ? "1" : "0";
  return out;
}

/**
 * The memo key of a `/meta` projection: its decision record, serialized —
 * or `undefined` when an input cannot be keyed exactly (then the request is
 * not memoized).
 */
export function metaDecisionKey(
  input: MetaDecisionInput,
  ctx: MetaRecordContext,
): string | undefined {
  try {
    const seen = new Set<object>();
    checkScopes(input.writeScopes, seen);
    checkScopes(input.readScopes, seen);
    const p = input.projection;
    if (!p) return JSON.stringify([bits(input.actions), bits(input.crud)]);
    const refTargets: unknown[] = [];
    const types = [...p.refTargets.keys()].toSorted((a, b) => idOf(a) - idOf(b));
    for (const type of types) {
      const vis = p.refTargets.get(type);
      refTargets.push(
        idOf(type),
        ctx.isServed(type),
        vis ? encodeLevel(vis, NO_TREE, ctx, seen, 1) : 0,
      );
    }
    const { writable, nestedWrites, forced } = p;
    const controls: unknown[] = [];
    for (const op of Object.keys(p.controls).toSorted()) {
      const policy = p.controls[op] ?? {};
      const gates: unknown[] = [op];
      for (const key of Object.keys(policy).toSorted()) {
        const gate = policy[key];
        if (typeof gate !== "boolean" && !Array.isArray(gate)) refuse();
        gates.push(key, Array.isArray(gate) ? sortedNames(gate) : gate);
      }
      controls.push(gates);
    }
    return JSON.stringify([
      bits(input.actions),
      bits(input.crud),
      encodeLevel(p.vis, p.tree, ctx, seen, 0),
      writable === undefined ? 0 : writable === "all" ? 1 : sortedNames(writable),
      nestedWrites ? sortedNames(nestedWrites) : 0,
      forced ? sortedNames(forced) : 0,
      controls,
      refTargets,
      p.vis.table?.type ? ctx.isServed(p.vis.table.type) : 0,
    ]);
  } catch (error) {
    if (error instanceof Unkeyable) return undefined;
    throw error;
  }
}

// Envelope → decision key → projected `/meta` (LRU, insertion order).
const variants = new WeakMap<object, Map<string, TMetaResponse>>();
// Envelopes seen once: memoize from the second sight on, so a caller passing
// a fresh object per request never fills the memo (or prerenders) for nothing.
const seenEnvelopes = new WeakSet<object>();

/**
 * The projection of `envelope` for `key`, computed once per (envelope, key)
 * and reused while it stays among the `max` most recently used. No `key`
 * (unkeyable decisions) or `max` ≤ 0 → computed per call, uncached.
 */
export function memoMetaProjection(
  envelope: object,
  key: string | undefined,
  max: number,
  compute: () => TMetaResponse,
): TMetaResponse {
  if (key === undefined || max <= 0) return compute();
  if (!seenEnvelopes.has(envelope)) {
    seenEnvelopes.add(envelope);
    return compute();
  }
  let byKey = variants.get(envelope);
  const hit = byKey?.get(key);
  if (hit) {
    byKey!.delete(key);
    byKey!.set(key, hit);
    return hit;
  }
  const out = shareMeta(compute());
  if (!byKey) variants.set(envelope, (byKey = new Map()));
  while (byKey.size >= max) byKey.delete(byKey.keys().next().value!);
  byKey.set(key, out);
  return out;
}

/**
 * Make a memoized `/meta` object shareable across requests: moost-db's
 * `stableMeta()` deep-freezes it and marks it identity-stable, so every later
 * `/meta` step memoizes on it and `GET /meta` serves it (or the step's
 * memoized output) serialized once, with a weak ETag.
 */
export function shareMeta<T extends object>(obj: T): T {
  return stableMeta(obj);
}
