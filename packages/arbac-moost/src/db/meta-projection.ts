import { effectiveScope } from "@aooth/arbac";
import type { ControlGate } from "@aooth/arbac";
import { translateQueryTree } from "@atscript/db";
import type { AtscriptQueryNode, TCrudOp, TMetaResponse } from "@atscript/db";
import { DB_CRUD_HANDLERS, resolveTerminalRef, VALUE_HELP_CRUD_HANDLERS } from "@atscript/moost-db";
import type { TDbIndexFieldPaths } from "@atscript/moost-db";
import type {
  TAtscriptAnnotatedType,
  TSerializedAnnotatedType,
  TSerializedAnnotatedTypeInner,
} from "@atscript/typescript/utils";
import { getConstructor, getMoostMate, useControllerContext } from "moost";

import { arbacIdsFromMeta, currentMoostArbac } from "../arbac.evaluate";
import type { TArbacMeta } from "../arbac.mate";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate, hasSelfOrAncestor, navFieldsOf } from "./helpers";
import { memoMetaProjection, metaDecisionKey } from "./meta-memo";
import type { MetaRecordContext } from "./meta-memo";
import {
  evaluateHandlers,
  evaluateTypeRead,
  isArbacServedType,
  resolveHandlerArbacIds,
  resolveRelationTree,
} from "./relation-policy";
import type { ArbacHandlerIds, RelationNameTree } from "./relation-policy";
import {
  buildScopeVisibility,
  collectWritableFields,
  identifierSet,
  isIdentifierSet,
  isMetaFieldVisible,
  tablePolicy,
  visibleRelation,
} from "./visibility";
import type { MetaVisibility, VisibilityTableSource } from "./visibility";

/**
 * Exact-or-ancestor membership in the write whitelist: `credit.credentials.user`
 * matches a `credit.credentials` grant. A path through a nav relation is
 * writable only when the relation is opted into nested writes
 * ({@link MetaVisibility.nestedWrites}); a `@db.column.derived` field never is
 * (its payload value is dropped).
 */
function isPathWritable(path: string, vis: MetaVisibility): boolean {
  const writable = vis.writable;
  if (!writable || tablePolicy(vis.table).derived.has(path)) return false;
  if (isForced(path, vis)) return false;
  const dot = path.indexOf(".");
  const head = dot === -1 ? path : path.slice(0, dot);
  const isRelation = vis.relationNames?.has(head) || vis.table?.navFields?.has(head);
  if (isRelation && !vis.nestedWrites?.has(head)) return false;
  return writable === "all" || hasSelfOrAncestor(writable, path);
}

/** `path` (or an ancestor) is pinned by the write scopes' `set` — see {@link MetaVisibility.forced}. */
function isForced(path: string, vis: MetaVisibility): boolean {
  return !!vis.forced?.size && hasSelfOrAncestor(vis.forced, path);
}

/**
 * Foreign `ref` targets for `/meta` pruning: annotated type → the caller's
 * visibility on it, or `null` when the caller cannot read it.
 */
export type MetaRefTargets = ReadonlyMap<object, MetaVisibility | null>;

/**
 * Prune a `/meta` envelope down to the fields the principal's read scopes can
 * ever surface, so a scoped UI cannot even OFFER an out-of-scope column (the
 * designed contract: the projection removes fields from the META entirely,
 * not just from row payloads). Pruned facets:
 *
 * - `fields` — the flat capability map (sortable/filterable flags).
 * - `type` — the serialized annotated type (what dynamic clients build
 *   tables/forms from); nested object props prune by dot-path. A visible
 *   relation's nav prop is pruned by that relation's visibility (declared
 *   sub-scope or the caller's own grant on the target), recursively. A
 *   `ref` whose target field is hidden (own table) or whose target table the
 *   caller cannot read (`refTargets`) is stripped.
 * - `relations` — hidden relations dropped.
 * - `versionColumn` — dropped when the OCC column itself is hidden.
 *
 * NEVER mutates the input — the base controller caches the static envelope
 * (`applyMetaOverlay` contract); every pruned branch is a fresh object.
 */
export function pruneMetaByVisibility(
  meta: TMetaResponse,
  vis: MetaVisibility,
  refTargets?: MetaRefTargets,
): TMetaResponse {
  const fields: TMetaResponse["fields"] = {};
  for (const [path, fieldMeta] of Object.entries(meta.fields)) {
    if (isMetaFieldVisible(path, vis)) {
      fields[path] = fieldMeta;
    } else if (isPathWritable(path, vis)) {
      // Writable-but-unreadable: keep the descriptor as write-only. Reads
      // still never surface it (the read projection stands); filter/sort are
      // off so it can't be probed.
      fields[path] = { ...fieldMeta, writeOnly: true, filterable: false, sortable: false };
    }
  }

  // A top-level relation name IS its own path head.
  const relationNames = new Set(meta.relations.map((r) => r.name));
  const relations = meta.relations.filter((r) => isMetaFieldVisible(r.name, vis));

  const out: TMetaResponse = {
    ...meta,
    fields,
    relations,
    type: pruneSerializedType(inlineTypeRefs(meta.type), {
      basePath: "",
      vis,
      relationNames,
      refTargets,
    }) as TSerializedAnnotatedType,
  };
  if (out.versionColumn !== undefined && !isMetaFieldVisible(out.versionColumn, vis)) {
    delete out.versionColumn;
  }
  return out;
}

/**
 * Replace every `$ref` entry with a copy of the body serialized under its `id`
 * (the first node carrying that id), so each use is pruned by ITS OWN path's
 * visibility. A shared body pruned once would resolve, on the client, to the
 * first use's shape at every other use: hidden fields leak through a later
 * `$ref`, and a hidden first use leaves later `$ref`s dangling. An `own`
 * entry keeps its own metadata / optional / `ref`. Unknown ids and recursive
 * back-references stay `$ref`s (a recursive one points at an ancestor that is
 * itself retained). Never mutates the (cached) input.
 */
function inlineTypeRefs<T extends TSerializedAnnotatedTypeInner>(root: T): T {
  return getOrCreate(inlinedCache, root, () => {
    const bodies = new Map<string, TSerializedAnnotatedTypeInner>();
    collectBodies(root, bodies);
    if (bodies.size === 0) return root;
    const ctx: InlineCtx = { bodies, budget: MAX_INLINED_NODES, n: 0 };
    return inlineNode(root, ctx, new Map(), false) ?? root;
  }) as T;
}

// Per static envelope type (identity-stable): the relation names / ref targets
// and the pruning must all walk the SAME inlined tree.
const inlinedCache = new WeakMap<object, TSerializedAnnotatedTypeInner>();

type TypeNode = TSerializedAnnotatedTypeInner;

/**
 * Total nodes that may be materialised by inlining `$ref` bodies. A DAG schema
 * that reuses a type at several levels inlines exponentially; past the budget
 * the affected fields are dropped (fail closed), never left unpruned.
 */
export const MAX_INLINED_NODES = 20_000;

interface InlineCtx {
  bodies: Map<string, TypeNode>;
  budget: number;
  n: number;
}

function childNodes(node: TypeNode): TypeNode[] {
  const def = node.type as unknown as Record<string, unknown>;
  const out: TypeNode[] = [];
  if (def.kind === "object") {
    out.push(...Object.values(def.props as Record<string, TypeNode>));
    for (const p of (def.propsPatterns as Array<{ def: TypeNode }> | undefined) ?? []) {
      out.push(p.def);
    }
  } else if (def.kind === "array") out.push(def.of as TypeNode);
  else if (Array.isArray(def.items)) out.push(...(def.items as TypeNode[]));
  const refType = node.ref?.type as TypeNode | undefined;
  if (refType && (refType as { type?: unknown }).type) out.push(refType);
  return out;
}

function collectBodies(node: TypeNode, bodies: Map<string, TypeNode>): void {
  if (node.type.kind === "$ref") return;
  if (node.id !== undefined && !bodies.has(node.id)) bodies.set(node.id, node);
  for (const child of childNodes(node)) collectBodies(child, bodies);
}

function inlineNode(
  node: TypeNode,
  ctx: InlineCtx,
  stack: ReadonlyMap<string, string>,
  inlining: boolean,
): TypeNode | undefined {
  const def = node.type;
  if (def.kind === "$ref") {
    const ancestor = stack.get(def.id);
    // Recursive back-reference: point it at THIS copy's own ancestor id.
    if (ancestor !== undefined) return { ...node, type: { ...def, id: ancestor } };
    const body = ctx.bodies.get(def.id);
    if (!body) return node;
    const inlined = inlineNode(body, ctx, stack, true);
    if (!inlined) return undefined;
    if (!def.own) return inlined;
    const { ref: _ref, optional: _optional, ...rest } = inlined;
    return {
      ...rest,
      metadata: node.metadata,
      ...(node.optional === undefined ? {} : { optional: node.optional }),
      ...(node.ref ? { ref: node.ref } : {}),
    };
  }
  if (inlining && --ctx.budget < 0) return undefined; // fail closed: drop, never keep unpruned
  // Every id-bearing node gets a unique id, so a copy pruned for one path can
  // never be what another copy's back-reference resolves to client-side.
  let nextStack = stack;
  let out: TypeNode = node;
  if (node.id !== undefined) {
    const copyId = `${node.id}#${++ctx.n}`;
    nextStack = new Map(stack).set(node.id, copyId);
    out = { ...node, id: copyId };
  }
  const d = def as unknown as Record<string, unknown>;
  if (d.kind === "object") {
    const props: Record<string, TypeNode> = {};
    for (const [k, v] of Object.entries(d.props as Record<string, TypeNode>)) {
      const r = inlineNode(v, ctx, nextStack, inlining);
      if (r) props[k] = r;
    }
    const propsPatterns: Array<{ def: TypeNode }> = [];
    for (const p of (d.propsPatterns as Array<{ def: TypeNode }> | undefined) ?? []) {
      const r = inlineNode(p.def, ctx, nextStack, inlining);
      if (r) propsPatterns.push({ ...p, def: r });
    }
    out = { ...out, type: { ...def, props, propsPatterns } as typeof def };
  } else if (d.kind === "array") {
    const of = inlineNode(d.of as TypeNode, ctx, nextStack, inlining) ?? emptyStub();
    out = { ...out, type: { ...def, of } as typeof def };
  } else if (Array.isArray(d.items)) {
    const items = (d.items as TypeNode[]).map(
      (i) => inlineNode(i, ctx, nextStack, inlining) ?? emptyStub(),
    );
    out = { ...out, type: { ...def, items } as typeof def };
  }
  const refType = out.ref?.type as TypeNode | undefined;
  if (out.ref && refType && (refType as { type?: unknown }).type) {
    const r = inlineNode(refType, ctx, nextStack, inlining);
    if (r) out = { ...out, ref: { ...out.ref, type: r } };
    else {
      const { ref: _r, ...noRef } = out;
      out = noRef;
    }
  }
  return out;
}

/** A body-less placeholder for a positional child dropped by the inline budget. */
function emptyStub(): TypeNode {
  return {
    $v: 2,
    type: { kind: "object", props: {}, propsPatterns: [], tags: [] },
    metadata: {},
  } as unknown as TypeNode;
}

/**
 * Copy-on-prune walk over a serialized type node. `basePath` is the flattened
 * dot-path prefix ("" at the root). Relation props (nav props named in
 * `meta.relations` at the root, or carrying a `db.rel.*` annotation inside a
 * joined type) are dropped when invisible and pruned by the relation's
 * visibility otherwise (a hand-built visibility without one keeps them
 * whole). Own-field subtrees prune recursively so an include-mode union like
 * `{ "password.hash": 1 }` keeps `password` with only `hash` inside.
 */
interface PruneLevel {
  /** The flattened dot-path prefix (`""` at a table root). */
  basePath: string;
  vis: MetaVisibility;
  /** The relation names of the level's table (nav props at its root). */
  relationNames: ReadonlySet<string>;
  refTargets: MetaRefTargets | undefined;
  /** Inside a union / intersection / tuple branch (flat-map entries are merged across branches). */
  inBranch?: boolean;
}

function pruneSerializedType(
  node: TSerializedAnnotatedTypeInner,
  level: PruneLevel,
): TSerializedAnnotatedTypeInner {
  const { basePath, vis, relationNames, refTargets } = level;
  const def = node.type;
  if (def.kind === "object") {
    const props: Record<string, TSerializedAnnotatedTypeInner> = {};
    for (const [name, prop] of Object.entries(def.props)) {
      const path = basePath ? `${basePath}.${name}` : name;
      if (basePath === "" && (relationNames.has(name) || isNavProp(prop))) {
        if (!isMetaFieldVisible(name, vis)) {
          // Unreadable but opted into nested writes (`nestedWrites`): keep
          // the shape, stamped write-only. Any other relation is no write
          // affordance — its nested writes answer 403.
          if (vis.nestedWrites?.has(name) && isPathWritable(name, vis)) {
            props[name] = stampWriteOnly(prop);
          }
          continue;
        }
        const sub = vis.relation?.(name);
        props[name] = sub
          ? pruneSerializedType(prop, {
              basePath: "",
              vis: sub,
              relationNames: sub.relationNames ?? NO_NAMES,
              refTargets,
            })
          : prop;
        continue;
      }
      const child = { ...level, basePath: path };
      if (!isMetaFieldVisible(path, vis)) {
        if (isPathWritable(path, vis)) {
          // Keep the whole subtree (clients need the full shape to WRITE it),
          // stamped write-only so forms render set-only inputs.
          props[name] = withVisibleTargets(
            stampWriteOnly(prop),
            path,
            vis,
            refTargets,
            level.inBranch,
          );
        } else if (hasWritableDescendant(path, vis.writable)) {
          // A hidden parent of writable leaves: keep only those (the walk
          // below drops every other hidden child), stamped write-only.
          props[name] = withVisibleTargets(
            stampWriteOnly(pruneSerializedType(prop, child)),
            path,
            vis,
            refTargets,
            level.inBranch,
          );
        }
        continue;
      }
      const pruned = pruneSerializedType(prop, child);
      props[name] = withVisibleTargets(
        isForced(path, vis) ? stampReadOnly(pruned) : pruned,
        path,
        vis,
        refTargets,
        level.inBranch,
      );
    }
    const pruned = { ...node, type: { ...def, props } };
    // Wildcard props of a table-level object (a nested object's patterns are gated with its prop).
    if (basePath !== "" || !def.propsPatterns?.length || !vis.table?.flatMap || !refTargets) {
      return pruned;
    }
    const runtime = level.inBranch ? undefined : (vis.table?.type as TAtscriptAnnotatedType);
    return gateChildren(pruned, runtime, vis, refTargets, false);
  }
  if (def.kind === "array") {
    return { ...node, type: { ...def, of: pruneSerializedType(def.of, level) } };
  }
  if (def.kind === "union" || def.kind === "intersection" || def.kind === "tuple") {
    return {
      ...node,
      type: {
        ...def,
        items: def.items.map((item) => pruneSerializedType(item, { ...level, inBranch: true })),
      },
    };
  }
  return node;
}

function stampWriteOnly(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  return { ...node, metadata: { ...node.metadata, "db.writeOnly": true } };
}

function stampReadOnly(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  return { ...node, metadata: { ...node.metadata, "meta.readonly": true } };
}

/** A strict descendant of `path` is in the write whitelist. */
function hasWritableDescendant(path: string, writable: MetaVisibility["writable"]): boolean {
  if (!writable || writable === "all") return false;
  const prefix = `${path}.`;
  for (const f of writable) if (f.startsWith(prefix)) return true;
  return false;
}

function withoutRef(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  const { ref: _ref, ...rest } = node;
  return rest;
}

/** The `/meta` annotation key of a dictionary value-help binding (`@ui.valueHelp`, since 0.1.75); a string constant — arbac-moost does not import `@atscript/ui`. */
const UI_VALUE_HELP = "ui.valueHelp";

/** A table a field points at, and the fields it names there. */
interface Target {
  type: object;
  fields: string[];
}

function withoutBinding(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  const { [UI_VALUE_HELP]: _binding, ...metadata } = node.metadata;
  return { ...node, metadata };
}

// Per runtime flat-map entry: static, so resolved once (`null` = no binding).
const bindingCache = new WeakMap<object, Target | null>();

/**
 * The runtime `ui.valueHelp` binding of a flat-map entry — the dictionary and
 * the fields it names there: the committed `field` plus every field its
 * static filter reads. `undefined` = no binding; `null` = a binding that
 * cannot be resolved (callers fail closed and strip it).
 */
function bindingOf(entry: unknown): Target | null | undefined {
  const raw = (entry as TAtscriptAnnotatedType | undefined)?.metadata?.get?.(UI_VALUE_HELP) as
    | { target?: unknown; field?: unknown; filter?: AtscriptQueryNode }
    | undefined;
  if (!raw) return undefined;
  let binding = bindingCache.get(entry as object);
  if (binding === undefined) {
    binding = resolveBinding(raw);
    bindingCache.set(entry as object, binding);
  }
  return binding;
}

function resolveBinding(raw: {
  target?: unknown;
  field?: unknown;
  filter?: AtscriptQueryNode;
}): Target | null {
  try {
    const t = raw.target as (() => object) | { type: () => object } | undefined;
    const type = typeof t === "function" ? t() : t?.type();
    if (!type) return null;
    const fields = typeof raw.field === "string" ? [raw.field] : [];
    if (raw.filter) {
      translateQueryTree(raw.filter, (ref) => {
        fields.push(ref.field);
        return ref.field;
      });
    }
    return { type, fields };
  } catch {
    return null;
  }
}

/** Every table a flat-map entry points at: its `ref` target and its value-help binding. */
function targetsOf(entry: unknown): Target[] {
  const ref = refTargetOf(entry);
  const binding = bindingOf(entry);
  return [ref, binding].filter((t): t is Target => !!t);
}

/** The field a runtime prop's `ref` finally points at (the same terminal `/meta` serializes). */
function refTargetOf(entry: unknown): Target | undefined {
  const def = entry as TAtscriptAnnotatedType | undefined;
  if (!def?.ref) return undefined;
  const terminal = resolveTerminalRef(def);
  if (terminal) return { type: terminal.type, fields: terminal.field ? [terminal.field] : [] };
  try {
    const { type, field } = def.ref;
    return { type: type(), fields: field ? [field] : [] };
  } catch {
    return undefined;
  }
}

/**
 * Whether a no-field target type is table-served (so its read visibility must
 * be checked). Decided from STABLE information only, never from the runtime
 * `db.http.path` metadata: moost-db mirrors it after init, deletes it for an
 * ambiguous model and rewrites it when another app publishes, so a pure
 * value-help dictionary whose only `db.*` key is that mirror would flip.
 * Served when (1) an ARBAC controller of THIS app is registered for the type
 * (fail closed: guarded here => readability is checked), or (2) the schema
 * declares a `db.*` annotation other than `db.http.path` (`db.table`,
 * `db.view`, ...).
 */
function isDbServed(type: object): boolean {
  if (isArbacServedType(type)) return true;
  const meta = (type as TAtscriptAnnotatedType).metadata as
    | ReadonlyMap<string, unknown>
    | undefined;
  if (!meta || typeof meta.keys !== "function") return false;
  for (const key of meta.keys()) if (key.startsWith("db.") && key !== "db.http.path") return true;
  return false;
}

/**
 * A target survives when the caller can read its table AND see every field it
 * names: a self-target against this level's visibility, a foreign one against
 * the caller's visibility on that table (`refTargets`; unreadable → hidden). A
 * target naming no field (a prop typed as a table interface, `@db.json snap?:
 * Dict`) still needs the table readable, unless the type is not table-served.
 */
function isTargetVisible(target: Target, vis: MetaVisibility, refTargets: MetaRefTargets): boolean {
  if (target.fields.length === 0 && !isDbServed(target.type)) return true;
  const targetVis = target.type === vis.table?.type ? vis : refTargets.get(target.type);
  return !!targetVis && target.fields.every((f) => isMetaFieldVisible(f, targetVis));
}

/** The binding on the TYPE a `ref` points at (an alias such as `@ui.valueHelp X type Code = string`). */
function refTypeBindingOf(entry: unknown): Target | null | undefined {
  try {
    const type = (entry as TAtscriptAnnotatedType | undefined)?.ref?.type?.();
    return type ? bindingOf(type) : null;
  } catch {
    return null;
  }
}

/** Both targets of one node: stripped = hidden. The serialized `ref.type` carries its own metadata. */
function gateOwn(
  node: TSerializedAnnotatedTypeInner,
  entry: unknown,
  visible: (target: Target) => boolean,
): TSerializedAnnotatedTypeInner {
  let out = node;
  if (out.ref) {
    const ref = refTargetOf(entry);
    if (!ref || !visible(ref)) out = withoutRef(out);
  }
  if (out.metadata?.[UI_VALUE_HELP] !== undefined) {
    const binding = bindingOf(entry);
    // `undefined` (miss) / `null` (unresolvable target): strip.
    if (!binding || !visible(binding)) out = withoutBinding(out);
  }
  const refMeta = out.ref?.type?.metadata;
  if (out.ref && refMeta?.[UI_VALUE_HELP] !== undefined) {
    const binding = refTypeBindingOf(entry);
    if (!binding || !visible(binding)) {
      const { [UI_VALUE_HELP]: _b, ...metadata } = refMeta;
      out = { ...out, ref: { ...out.ref, type: { ...out.ref.type, metadata } } };
    }
  }
  return out;
}

/**
 * Gate the children of `node` a prop walk does not reach by flat path: array
 * elements, union / intersection / tuple members and wildcard props — each
 * paired with its runtime counterpart under `runtime` (a missing one fails
 * closed). `deep` also descends object props (own-field subtrees only; a nav
 * prop belongs to its own level).
 */
function gateChildren(
  node: TSerializedAnnotatedTypeInner,
  runtime: TAtscriptAnnotatedType | undefined,
  vis: MetaVisibility,
  refTargets: MetaRefTargets,
  deep: boolean,
): TSerializedAnnotatedTypeInner {
  const visible = (t: Target) => isTargetVisible(t, vis, refTargets);
  const gate = (child: TSerializedAnnotatedTypeInner, rt: TAtscriptAnnotatedType | undefined) =>
    gateChildren(gateOwn(child, rt, visible), rt, vis, refTargets, true);
  const rtType = runtime?.type as
    | {
        props?: Map<string, TAtscriptAnnotatedType>;
        propsPatterns?: Array<{ pattern: RegExp; def: TAtscriptAnnotatedType }>;
        of?: TAtscriptAnnotatedType;
        items?: TAtscriptAnnotatedType[];
      }
    | undefined;
  const def = node.type as any;
  if (def.kind === "object") {
    let next = def;
    if (deep && def.props) {
      const props: Record<string, TSerializedAnnotatedTypeInner> = {};
      for (const [name, prop] of Object.entries(def.props as Record<string, any>)) {
        props[name] = isNavProp(prop) ? prop : gate(prop, rtType?.props?.get?.(name));
      }
      next = { ...next, props };
    }
    if (def.propsPatterns?.length) {
      const patterns = def.propsPatterns.map((p: any) => {
        const rt = rtType?.propsPatterns?.find(
          (r) => r.pattern?.source === p.pattern?.source && r.pattern?.flags === p.pattern?.flags,
        )?.def;
        return { ...p, def: gate(p.def, rt) };
      });
      next = { ...next, propsPatterns: patterns };
    }
    return next === def ? node : { ...node, type: next };
  }
  if (def.kind === "array") {
    return { ...node, type: { ...def, of: gate(def.of, rtType?.of) } };
  }
  if (Array.isArray(def.items)) {
    const items = def.items.map((item: any, i: number) => gate(item, rtType?.items?.[i]));
    return { ...node, type: { ...def, items } };
  }
  return node;
}

/**
 * Strip a serialized `ref` / `ui.valueHelp` binding at `path` — on the prop
 * itself, on a `ref` target's own metadata, and on every array element, union
 * / intersection / tuple member and wildcard prop below it — whose target is
 * hidden from the caller. Without runtime schema info (`vis.table.flatMap`) or
 * `refTargets`, all are kept.
 */
function withVisibleTargets(
  node: TSerializedAnnotatedTypeInner,
  path: string,
  vis: MetaVisibility,
  refTargets: MetaRefTargets | undefined,
  ambiguous = false,
): TSerializedAnnotatedTypeInner {
  const flatMap = vis.table?.flatMap;
  if (!flatMap || !refTargets || !serializedHasTarget(node)) return node;
  // Fail closed: a union/intersection/tuple branch shares one merged flat
  // entry with same-named props of its sibling branches, so the entry cannot
  // be trusted to describe THIS node; and a flat-map miss describes nothing.
  const entry = ambiguous ? undefined : (flatMap.get(path) as TAtscriptAnnotatedType | undefined);
  const out = gateOwn(node, entry, (t) => isTargetVisible(t, vis, refTargets));
  return gateChildren(out, entry, vis, refTargets, false);
}

const NO_NAMES: ReadonlySet<string> = new Set();

/** A nav prop inside a joined type: atscript-db stamps `db.rel.to` / `from` / `via`. */
function isNavProp(prop: TSerializedAnnotatedTypeInner): boolean {
  const meta = prop.metadata as Record<string, unknown> | undefined;
  return !!meta && ("db.rel.to" in meta || "db.rel.from" in meta || "db.rel.via" in meta);
}

/**
 * The write CRUD ops. Everything else in `meta.crud` is row-returning read
 * surface whose scopes govern field VISIBILITY in `/meta` — classified by
 * complement so a read op added upstream defaults to READ and the pruning
 * fails closed (a principal whose only read grant is the new op still gets
 * a pruned envelope rather than the full field map).
 */
const WRITE_CRUD_OPS: ReadonlySet<TCrudOp> = new Set<TCrudOp>([
  "insert",
  "update",
  "replace",
  "remove",
]);

/**
 * The handler methods serving a `/meta` crud op on this controller (a DB or
 * value-help controller — moost-db's handler maps); an op is allowed when
 * ANY of them is. An op no map lists is its own method name.
 */
function crudHandlers(op: TCrudOp, methods: ReadonlySet<string>): readonly string[] {
  const found = [...(DB_CRUD_HANDLERS[op] ?? []), ...(VALUE_HELP_CRUD_HANDLERS[op] ?? [])].filter(
    (m) => methods.has(m),
  );
  return found.length > 0 ? found : [op];
}

/**
 * The full ARBAC `/meta` overlay, shared by the ARBAC DB and value-help
 * controllers.
 *
 * 1. `actions` and `crud` are filtered by evaluating each one exactly as its
 *    handler is authorized (`useArbac` precedence): a crud op through its
 *    handler method(s) — `one` via `getOne` / `getOneComposite`, `remove`
 *    via `remove` / `removeComposite` (allowed when any is) — and an action
 *    through its method (`@ArbacAction` → `@DbAction` name → …).
 * 2. The FIELD surface (`fields`, serialized `type`, `relations`,
 *    `versionColumn`) is pruned by the read scopes' visibility: the
 *    projection union, derived-column sources, atomic JSON columns, and the
 *    `$with` relation policy (declared `with` sub-scopes, else the caller's
 *    own grant on the related table — no grant → relation and nav type
 *    dropped). `ref`s to hidden targets are stripped. An allowed read op
 *    without scopes is an unscoped grant (no field restriction; relations
 *    still follow the relation policy). No read op allowed → no pruning:
 *    `crud` already advertises no read surface, and write-only principals
 *    still need `type` for their insert/update forms. PK + `preferredId` are
 *    never pruned.
 *
 * 3. The capabilities (`crud[op]` control lists, field `groupable` /
 *    `bucketable` / `numeric` / `sortable`, relation `filterable`, the
 *    aggregate and search envelope keys) follow each read op's `controls` policy
 *    ({@link gateMetaControls}).
 *
 * The search surface (`searchIndexes`, `searchable`, `vectorSearchable`,
 * `geoSearchable`) is also narrowed by moost-db itself (≥ 0.1.147, under the
 * overridden `hasField`), after this overlay.
 *
 * @param source - the controller's `this.readable` (identifiers, relations
 *   and schema rules are derived from it); an identifier set (the 0.1.67
 *   signature) still works, without them
 * @param _indexes - @deprecated ignored since 0.1.74 (moost-db prunes the search surface)
 */
export async function applyArbacMetaOverlay(
  meta: TMetaResponse,
  source: VisibilityTableSource | ReadonlySet<string>,
  _indexes?: readonly TDbIndexFieldPaths[],
): Promise<TMetaResponse> {
  const instance = useControllerContext().getController();
  const { methods } = controllerMethodIndex(instance);

  const crudKeys = Object.keys(meta.crud) as TCrudOp[];
  const [allowedActions, crudScopes, arbac] = await Promise.all([
    grantedActions(
      instance,
      meta.actions.map((entry) => entry.name),
    ),
    Promise.all(crudKeys.map((op) => evaluateHandlers(crudHandlerIds(instance, op, methods)))),
    currentMoostArbac(),
  ]);
  const memoMax = arbac.getMetaMemoMax();

  const allowed = new Set(allowedActions);
  const actionBits = meta.actions.map((entry) => allowed.has(entry.name));
  const crudBits = crudScopes.map((scopes) => scopes !== undefined);
  const readScopes: ArbacDbScope[] = [];
  const writeScopes: ArbacDbScope[] = [];
  // Each read op's own policy: `validateControls` enforces the op's scopes, not the union.
  const controls: Partial<Record<TCrudOp, Record<string, ControlGate>>> = {};
  for (let i = 0; i < crudKeys.length; i++) {
    const scopes = crudScopes[i];
    if (!scopes) continue;
    if (WRITE_CRUD_OPS.has(crudKeys[i])) {
      writeScopes.push(...scopes);
    } else {
      readScopes.push(...scopes);
      controls[crudKeys[i]] = effectiveScope(scopes).controls;
    }
  }
  const overlay = (): TMetaResponse => {
    const crud: TMetaResponse["crud"] = {};
    for (let i = 0; i < crudKeys.length; i++) {
      if (crudBits[i]) crud[crudKeys[i]] = meta.crud[crudKeys[i]];
    }
    return { ...meta, actions: meta.actions.filter((_, i) => actionBits[i]), crud };
  };
  if (readScopes.length === 0) {
    const key =
      memoMax > 0
        ? metaDecisionKey(
            { actions: actionBits, crud: crudBits, readScopes, writeScopes },
            RECORD_CTX,
          )
        : undefined;
    return memoMetaProjection(meta, key, memoMax, overlay);
  }
  const writable = collectWritableFields(writeScopes, false);
  const writeEffective = effectiveScope(writeScopes);
  const nestedWrites = writeEffective.nestedWrites;
  const forced = writeEffective.set ? new Set(Object.keys(writeEffective.set)) : undefined;
  if (isIdentifierSet(source)) {
    // The 0.1.67 identifier-set signature: no table to key on — not memoized.
    const vis = buildScopeVisibility(readScopes, undefined, source);
    const visible = Object.keys(vis.allowed).length > 0 || vis.withGrants.size > 0;
    const overlaid = overlay();
    return gateMetaControls(
      visible
        ? pruneMetaByVisibility(overlaid, { ...vis, writable, nestedWrites, forced })
        : overlaid,
      controls,
    );
  }

  const relations = await resolveRelationTree(readScopes, source, metaRelationNames(meta), {
    listSiblings: false,
  });
  const vis = buildScopeVisibility(readScopes, source, { relations });
  const refTargets = await resolveRefTargets(vis, meta);
  const key =
    memoMax > 0
      ? metaDecisionKey(
          {
            actions: actionBits,
            crud: crudBits,
            readScopes,
            writeScopes,
            projection: {
              vis,
              tree: metaRelationNames(meta),
              writable,
              nestedWrites,
              forced,
              controls,
              refTargets,
            },
          },
          RECORD_CTX,
        )
      : undefined;
  return memoMetaProjection(meta, key, memoMax, () =>
    gateMetaControls(
      pruneMetaByVisibility(overlay(), { ...vis, writable, nestedWrites, forced }, refTargets),
      controls,
    ),
  );
}

/** What the `/meta` memo's decision record reads from the pruning rules. */
const RECORD_CTX: MetaRecordContext = { isServed: isDbServed, identifiers: identifierSet };

/**
 * The `/meta/form/:name` overlay: a form is a plain annotated type (no table),
 * so only its cross-table pointers are projected. Every prop's `ref` and
 * `ui.valueHelp` binding is stripped when the caller cannot read the target
 * table, or cannot see a field the pointer names there (the same rule as the
 * `/meta` type); an unresolvable binding is stripped too. Never mutates
 * `serialized` (the base controller caches it); returns it itself when
 * nothing is stripped.
 *
 * @param serialized - the form's serialized schema as moost-db served it
 * @param formType - the runtime form type the schema was serialized from
 */
export async function applyArbacFormOverlay(
  serialized: TSerializedAnnotatedType,
  formType: TAtscriptAnnotatedType | undefined,
): Promise<TSerializedAnnotatedType> {
  if (!formType) return serialized;
  const types = new Set<object>();
  collectFormTargets(formType, serialized, types, 0);
  if (types.size === 0 && !hasUnresolvedBinding(formType, serialized, 0)) return serialized;
  const readable = new Map<object, MetaVisibility | null>();
  await Promise.all(
    [...types].map(async (type) => {
      const read = await evaluateTypeRead(type);
      readable.set(type, read ? buildScopeVisibility(read.scopes, read.table) : null);
    }),
  );
  return stripFormTargets(formType, serialized, readable, 0) as TSerializedAnnotatedType;
}

const formTargetsOf = (entry: TAtscriptAnnotatedType, node: TSerializedAnnotatedTypeInner) => {
  const out: Array<Target | null> = [];
  if (node.ref) {
    const ref = refTargetOf(entry);
    out.push(ref ?? null);
  }
  if (node.metadata?.[UI_VALUE_HELP] !== undefined) {
    const binding = bindingOf(entry);
    if (binding !== undefined) out.push(binding);
  }
  if (node.ref && node.ref.type?.metadata?.[UI_VALUE_HELP] !== undefined) {
    out.push(refTypeBindingOf(entry) ?? null);
  }
  return out;
};

/** Where a child sits in its parent: an object prop, the array element, or a union/intersection/tuple item. */
type FormChildKey = { prop: string } | { of: true } | { item: number } | { pattern: number };
type FormChild = [TAtscriptAnnotatedType, TSerializedAnnotatedTypeInner, FormChildKey];

/** Pairs the runtime and serialized trees over EVERY child container (props, of, items). */
function formChildren(
  runtime: TAtscriptAnnotatedType,
  node: TSerializedAnnotatedTypeInner,
): FormChild[] {
  const rt = runtime.type as {
    kind: string;
    props?: Map<string, TAtscriptAnnotatedType>;
    of?: TAtscriptAnnotatedType | TAtscriptAnnotatedType[];
    items?: TAtscriptAnnotatedType[];
    propsPatterns?: Array<{ pattern: RegExp; def: TAtscriptAnnotatedType }>;
  };
  const def = node.type as {
    props?: Record<string, TSerializedAnnotatedTypeInner>;
    of?: TSerializedAnnotatedTypeInner | TSerializedAnnotatedTypeInner[];
    items?: TSerializedAnnotatedTypeInner[];
    propsPatterns?: Array<{
      pattern: { source: string; flags: string };
      def: TSerializedAnnotatedTypeInner;
    }>;
  };
  const out: FormChild[] = [];
  if (rt.props && def.props) {
    for (const [name, child] of rt.props) {
      if (def.props[name]) out.push([child, def.props[name], { prop: name }]);
    }
  }
  if (rt.of && !Array.isArray(rt.of) && def.of && !Array.isArray(def.of)) {
    out.push([rt.of, def.of, { of: true }]);
  }
  if (Array.isArray(rt.items) && Array.isArray(def.items)) {
    rt.items.forEach((child, i) => def.items![i] && out.push([child, def.items![i], { item: i }]));
  }
  def.propsPatterns?.forEach((p, i) => {
    const match = rt.propsPatterns?.find(
      (r) => r.pattern?.source === p.pattern?.source && r.pattern?.flags === p.pattern?.flags,
    );
    if (match) out.push([match.def, p.def, { pattern: i }]);
  });
  return out;
}

/** Nested-relation walk bound — serialized nav bodies are finite, this only guards pathological input. */
const MAX_NAV_DEPTH = 8;

/** The form walk bound; past it every `ref` / binding is stripped (fail closed). */
const MAX_FORM_DEPTH = MAX_NAV_DEPTH * 2;

function serializedChildren(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner[] {
  const def = node.type as unknown as {
    props?: Record<string, TSerializedAnnotatedTypeInner>;
    of?: TSerializedAnnotatedTypeInner;
    items?: TSerializedAnnotatedTypeInner[];
    propsPatterns?: Array<{ def: TSerializedAnnotatedTypeInner }>;
  };
  return [
    ...Object.values(def.props ?? {}),
    ...(def.of ? [def.of] : []),
    ...(def.items ?? []),
    ...(def.propsPatterns ?? []).map((p) => p.def),
  ];
}

function serializedHasTarget(node: TSerializedAnnotatedTypeInner): boolean {
  return (
    !!node.ref ||
    node.metadata?.[UI_VALUE_HELP] !== undefined ||
    serializedChildren(node).some(serializedHasTarget)
  );
}

function stripAllTargets(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  if (!serializedHasTarget(node)) return node;
  let out = node;
  if (out.ref) out = withoutRef(out);
  if (out.metadata?.[UI_VALUE_HELP] !== undefined) out = withoutBinding(out);
  const def = out.type as any;
  const next: any = { ...def };
  if (def.props) {
    next.props = Object.fromEntries(
      Object.entries(def.props).map(([k, v]) => [k, stripAllTargets(v as never)]),
    );
  }
  if (def.of) next.of = stripAllTargets(def.of);
  if (def.items) next.items = def.items.map((i: never) => stripAllTargets(i));
  if (def.propsPatterns) {
    next.propsPatterns = def.propsPatterns.map((p: any) => ({ ...p, def: stripAllTargets(p.def) }));
  }
  return { ...out, type: next };
}

function collectFormTargets(
  runtime: TAtscriptAnnotatedType,
  node: TSerializedAnnotatedTypeInner,
  into: Set<object>,
  depth: number,
): void {
  if (depth >= MAX_FORM_DEPTH) return;
  for (const t of formTargetsOf(runtime, node)) if (t) into.add(t.type);
  for (const [child, childNode] of formChildren(runtime, node)) {
    collectFormTargets(child, childNode, into, depth + 1);
  }
}

function hasUnresolvedBinding(
  runtime: TAtscriptAnnotatedType,
  node: TSerializedAnnotatedTypeInner,
  depth: number,
): boolean {
  if (depth >= MAX_FORM_DEPTH) return serializedHasTarget(node); // past the cap everything is stripped
  if (formTargetsOf(runtime, node).includes(null)) return true;
  return formChildren(runtime, node).some(([c, n]) => hasUnresolvedBinding(c, n, depth + 1));
}

function stripFormTargets(
  runtime: TAtscriptAnnotatedType,
  node: TSerializedAnnotatedTypeInner,
  readable: ReadonlyMap<object, MetaVisibility | null>,
  depth: number,
): TSerializedAnnotatedTypeInner {
  if (depth >= MAX_FORM_DEPTH) return stripAllTargets(node);
  const visible = (t: Target | null | undefined) => {
    if (!t) return false;
    const targetVis = readable.get(t.type);
    return !!targetVis && t.fields.every((f) => isMetaFieldVisible(f, targetVis));
  };
  const out = gateOwn(node, runtime, (t) => visible(t));
  // Rebuild only the children that changed.
  const children = formChildren(runtime, node);
  let changed: TSerializedAnnotatedTypeInner["type"] | undefined;
  for (const [child, childNode, key] of children) {
    const next = stripFormTargets(child, childNode, readable, depth + 1);
    if (next === childNode) continue;
    const base = (changed ?? out.type) as any;
    if ("prop" in key) {
      changed = { ...base, props: { ...base.props, [key.prop]: next } };
    } else if ("pattern" in key) {
      changed = {
        ...base,
        propsPatterns: base.propsPatterns.map((o: any, i: number) =>
          i === key.pattern ? { ...o, def: next } : o,
        ),
      };
    } else if ("item" in key) {
      changed = {
        ...base,
        items: base.items.map((o: unknown, i: number) => (i === key.item ? next : o)),
      };
    } else {
      changed = { ...base, of: next };
    }
  }
  return changed ? { ...out, type: changed } : out;
}

/** A role's effective `controls` policy (`false` / whitelist per `$control`; absent ≡ allowed). */
type ControlsPolicy = Readonly<Record<string, ControlGate>>;

const NO_POLICY: ControlsPolicy = {};

/** `crud[op]` entries that are query parts of their own, never seen by the controls gate. */
const NOT_CONTROLS: ReadonlySet<string> = new Set(["filter", "insights"]);

/**
 * Whether `control` is unusable in an op listing `list` under `policy`: its
 * gate is `false`, or everything it qualifies is unusable (`$index` /
 * `$fuzzy` / `$vector` name how `$search` runs, `$threshold` bounds
 * `$vector`, `$rowOrder` orders `first()` / `last()` in an aggregate
 * `$select`, `$nulls` places NULLs in `$sort` and `$rowOrder` keys).
 */
function isControlOff(control: string, list: readonly string[], policy: ControlsPolicy): boolean {
  if (!NOT_CONTROLS.has(control) && policy[`$${control}`] === false) return true;
  const off = (c: string) => isControlOff(c, list, policy);
  switch (control) {
    case "index":
    case "fuzzy":
      return list.includes("search") && off("search");
    case "vector":
      return off("search");
    case "threshold":
      return off("vector");
    case "rowOrder":
      return off("groupBy") || off("select");
    case "nulls":
      return off("sort") && (!list.includes("rowOrder") || off("rowOrder"));
    default:
      return false;
  }
}

/** Envelope keys that advertise aggregate queries (`$groupBy`, aggregate / bucket `$select`). */
const AGGREGATE_ENVELOPE_KEYS = ["aggregateFns", "aggregateExpressions", "bucketUnits"] as const;

/**
 * The `/meta` capabilities follow each read op's `controls` policy (`policies`;
 * an op without one is unrestricted), mirroring the 403 `applyArbacControls`
 * raises on that op's requests:
 *
 * - `crud[op]` loses every control the op's policy makes unusable
 *   ({@link isControlOff});
 * - a capability flag stays when SOME op listing its controls keeps them
 *   (no op lists them → left as built): `groupable` (`groupBy`, and the
 *   field on that op's `$groupBy` whitelist, if any), `bucketable` (the same
 *   plus `select` — a bucket is checked as the field it buckets), `numeric`
 *   and the aggregate envelope keys (`groupBy` + `select`: every aggregate,
 *   calendar bucket or arithmetic `$select` is `$groupBy` use), `sortable`
 *   (`sort`), `nullsPlacement` (`nulls`), `searchable` + `searchIndexes`
 *   (`search`), `vectorSearchable` + the vector indexes (`search` +
 *   `vector`), the non-default text indexes (`search` + `index`), a
 *   relation's `filterable` (`filter` + `with`, and the relation on that
 *   op's `$with` whitelist, if any).
 *
 * Returns `meta` itself when nothing changes.
 *
 * @since 0.1.75 (`groupable`), 0.1.80 (the rest)
 */
export function gateMetaControls(
  meta: TMetaResponse,
  policies: Readonly<Partial<Record<TCrudOp, ControlsPolicy>>>,
): TMetaResponse {
  if (!Object.values(policies).some((p) => p && Object.keys(p).length > 0)) return meta;
  let changed = false;
  const crud: TMetaResponse["crud"] = {};
  const ops: Array<{ list: readonly string[]; kept: readonly string[]; policy: ControlsPolicy }> =
    [];
  for (const [op, list] of Object.entries(meta.crud) as [TCrudOp, string[]][]) {
    const policy = policies[op] ?? NO_POLICY;
    const kept = list.filter((c) => !isControlOff(c, list, policy));
    if (kept.length !== list.length) changed = true;
    crud[op] = kept;
    ops.push({ list, kept, policy });
  }
  /** Some op listing `controls` keeps them all (and `name` passes its `whitelist` gate). */
  const served = (controls: readonly string[], name?: string, whitelist = "$groupBy") => {
    const listing = ops.filter((o) => controls.every((c) => o.list.includes(c)));
    return (
      listing.length === 0 ||
      listing.some(({ kept, policy }) => {
        const gate = policy[whitelist];
        return (
          controls.every((c) => kept.includes(c)) &&
          (name === undefined || !Array.isArray(gate) || gate.includes(name))
        );
      })
    );
  };
  const aggregates = served(["groupBy", "select"]);
  const sortable = served(["sort"]);

  const fields: TMetaResponse["fields"] = {};
  for (const [path, field] of Object.entries(meta.fields)) {
    let next = field;
    const strip = (flag: "groupable" | "bucketable" | "numeric", keep: () => boolean) => {
      if (!next[flag] || keep()) return;
      const { [flag]: _dropped, ...rest } = next;
      next = rest;
    };
    strip("groupable", () => served(["groupBy"], path));
    strip("bucketable", () => served(["groupBy", "select"], path));
    strip("numeric", () => aggregates);
    if (!sortable && next.sortable) next = { ...next, sortable: false };
    if (next !== field) changed = true;
    fields[path] = next;
  }

  const out: TMetaResponse = { ...meta, fields, crud };
  // A relation filter (`$some` / `$none`) is `$with` use of the relation (`enforceRelationGates`).
  const unfilterable = (r: TMetaResponse["relations"][number]) =>
    r.filterable && !served(["filter", "with"], r.name, "$with");
  if (out.relations.some(unfilterable)) {
    out.relations = out.relations.map((r) => {
      if (!unfilterable(r)) return r;
      const { filterable: _filterable, ...rest } = r;
      return rest;
    });
    changed = true;
  }
  if (!aggregates) {
    for (const key of AGGREGATE_ENVELOPE_KEYS) {
      if (out[key] === undefined) continue;
      delete out[key];
      changed = true;
    }
  }
  if (out.nullsPlacement && !served(["nulls"])) {
    delete out.nullsPlacement;
    changed = true;
  }
  const search = served(["search"]);
  const vector = search && served(["search", "vector"]);
  const named = served(["search", "index"]);
  const all = out.searchIndexes ?? [];
  const indexes = all.filter((i) =>
    i.type === "vector" ? vector : search && (named || !!i.isDefault),
  );
  if (indexes.length !== all.length) {
    out.searchIndexes = indexes;
    changed = true;
  }
  if (out.searchable && !search) {
    out.searchable = false;
    changed = true;
  }
  if (out.vectorSearchable && !vector) {
    out.vectorSearchable = false;
    changed = true;
  }
  return changed ? out : meta;
}

// Per static envelope (the base controller caches it — identity-stable).
const metaNamesCache = new WeakMap<TMetaResponse, RelationNameTree>();

/** The relation names `/meta`'s serialized type reaches: root relations, then nav props of each nav body. */
function metaRelationNames(meta: TMetaResponse): RelationNameTree {
  return getOrCreate(metaNamesCache, meta, () => buildMetaRelationNames(meta));
}

function buildMetaRelationNames(meta: TMetaResponse): RelationNameTree {
  const tree: RelationNameTree = new Map();
  const rootProps = objectProps(inlineTypeRefs(meta.type));
  for (const r of meta.relations) {
    const nested = new Map() as RelationNameTree;
    tree.set(r.name, nested);
    const prop = rootProps?.[r.name];
    if (prop) collectNavNames(prop, nested, 0);
  }
  return tree;
}

function collectNavNames(
  node: TSerializedAnnotatedTypeInner,
  into: RelationNameTree,
  depth: number,
): void {
  if (depth >= MAX_NAV_DEPTH) return;
  const props = objectProps(node);
  if (!props) return;
  for (const [name, prop] of Object.entries(props)) {
    if (!isNavProp(prop)) continue;
    collectNavNames(
      prop,
      getOrCreate(into, name, () => new Map()),
      depth + 1,
    );
  }
}

/** The props of an object node (through arrays). */
function objectProps(
  node: TSerializedAnnotatedTypeInner,
): Record<string, TSerializedAnnotatedTypeInner> | undefined {
  const def = node.type;
  if (def.kind === "object") return def.props;
  if (def.kind === "array") return objectProps(def.of);
  return undefined;
}

/**
 * Foreign `ref` targets of every level the pruned `/meta` shows (the root
 * table and each visible relation's table): the caller's visibility on each
 * target table, or `null` when they cannot read it.
 */
async function resolveRefTargets(
  root: MetaVisibility,
  meta: TMetaResponse,
): Promise<MetaRefTargets> {
  const types = new Set<object>();
  const visit = (vis: MetaVisibility, node: TSerializedAnnotatedTypeInner, depth: number) => {
    if (vis.table) for (const type of foreignRefTypes(vis.table)) types.add(type);
    const props = objectProps(node);
    if (!props || depth >= MAX_NAV_DEPTH) return;
    for (const name of new Set([...(vis.relationNames ?? NO_NAMES), ...vis.withGrants])) {
      const prop = props[name];
      if (!prop) continue;
      const sub = visibleRelation(name, vis);
      if (sub) visit(sub, prop, depth + 1);
    }
  };
  visit(root, inlineTypeRefs(meta.type), 0);
  const out = new Map<object, MetaVisibility | null>();
  await Promise.all(
    [...types].map(async (type) => {
      const read = await evaluateTypeRead(type);
      out.set(type, read ? buildScopeVisibility(read.scopes, read.table) : null);
    }),
  );
  return out;
}

// Per table: the annotated types its own (non-nav) fields `ref` into or bind value help to.
const refTypesCache = new WeakMap<VisibilityTableSource, ReadonlySet<object>>();

function foreignRefTypes(table: VisibilityTableSource): ReadonlySet<object> {
  const flatMap = table.flatMap;
  if (!flatMap) return NO_TYPES;
  return getOrCreate(refTypesCache, table, () => {
    const nav = navFieldsOf(table);
    const out = new Set<object>();
    for (const [path, entry] of flatMap) {
      if (hasSelfOrAncestor(nav, path)) continue;
      for (const target of targetsOf(entry)) {
        if (target.type !== table.type) out.add(target.type);
      }
    }
    return out;
  });
}

const NO_TYPES: ReadonlySet<object> = new Set();

interface ControllerMethodIndex {
  /** `@DbAction` name → the methods declaring it (absent for class-level action entries). */
  actionMethods: ReadonlyMap<string, readonly string[]>;
  /** Every method name on the instance's prototype chain. */
  methods: ReadonlySet<string>;
}

// Per-class memoization: controller and method decorator metadata are bound to
// the class at registration time and never mutate per-request.
const methodIndexCache = new WeakMap<Function, ControllerMethodIndex>();

/**
 * THE ARBAC ids an action is authorized as — used by the `/meta` overlay,
 * `authorizeForm`, `GET meta/actions` and `actionRowScope` alike: every
 * method declaring the `@DbAction` (allowed when ANY is — a union), each
 * with `useArbac()` precedence; a class-level `@DbActions` entry (no handler
 * method) → `{ resource: defaultResource, action: name }`. `defaultResource`
 * defaults to the controller's class-level resource.
 *
 * @since 0.1.72
 */
export function actionArbacIds(
  instance: object,
  name: string,
  defaultResource: string = controllerArbacResource(instance),
): ArbacHandlerIds[] {
  const methods = controllerMethodIndex(instance).actionMethods.get(name);
  return methods?.length
    ? methods.map((m) => resolveHandlerArbacIds(instance, m))
    : [{ resource: defaultResource, action: name }];
}

/**
 * The action `names` the caller holds a grant on — each evaluated as
 * {@link actionArbacIds} names it (memoized per event). THE action rule of
 * the `/meta` overlay, `allowedActions` (`$actions`, `GET meta/actions`).
 */
export async function grantedActions(
  instance: object,
  names: readonly string[],
): Promise<string[]> {
  const granted = await Promise.all(
    names.map((name) => evaluateHandlers(actionArbacIds(instance, name))),
  );
  return names.filter((_, i) => granted[i] !== undefined);
}

/** The controller's class-level ARBAC resource (`@ArbacResource` → controller id → class name). */
function controllerArbacResource(instance: object): string {
  return arbacIdsFromMeta(getMoostMate().read(instance), undefined, instance, "").resource;
}

/**
 * A controller class's methods and `@DbAction` name → methods map (memoized
 * per class). The method metadata is read from `instance` itself — never from
 * the event's current controller, which differs whenever another
 * controller's actions are evaluated in this event (a view's
 * `@DbActionsFrom` delegation).
 */
export function controllerMethodIndex(instance: object): ControllerMethodIndex {
  return getOrCreate(methodIndexCache, getConstructor(instance), () => {
    const mate = getMoostMate<TArbacMeta, TArbacMeta>();
    const methods = new Set(collectMethodNames(instance));
    const actionMethods = new Map<string, string[]>();
    for (const methodName of methods) {
      const name = mate.read(instance, methodName)?.atscript_db_action?.name;
      if (name) getOrCreate(actionMethods, name, () => []).push(methodName);
    }
    return { actionMethods, methods };
  });
}

/** The ARBAC ids of the handler method(s) serving crud op `op` on `instance` (`useArbac()` precedence). */
function crudHandlerIds(
  instance: object,
  op: TCrudOp,
  methods: ReadonlySet<string> = controllerMethodIndex(instance).methods,
): ArbacHandlerIds[] {
  return crudHandlers(op, methods).map((m) => resolveHandlerArbacIds(instance, m));
}

/**
 * The ARBAC ids of `instance`'s READ handler — the `query` crud op's
 * handler method(s), exactly what the `/meta` overlay evaluates for
 * `crud.query`.
 */
export function readHandlerIds(instance: object): ArbacHandlerIds[] {
  return crudHandlerIds(instance, "query");
}

/**
 * Test-friendly internal helper — exported for unit tests and helper
 * composition; regular consumers should not call this directly.
 *
 * Method names of an instance, walking the full prototype chain via property
 * DESCRIPTORS. Deliberately NOT moost's `getInstanceOwnMethods`: that helper
 * evaluates `instance[name]` for every property to test "is it a function",
 * which fires accessors — and moost-db's inherited `.table` getter THROWS for
 * view-bound controllers, turning every `/meta` request into a 500. Accessor
 * properties are skipped entirely (a getter-valued property is not a method
 * and can never carry `@DbAction` metadata).
 */
export function collectMethodNames(instance: object): string[] {
  const names = new Set<string>();
  let obj: object | null = instance;
  while (obj && obj !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(obj)) {
      if (name === "constructor") continue;
      const desc = Object.getOwnPropertyDescriptor(obj, name);
      if (desc && typeof desc.value === "function") names.add(name);
    }
    obj = Object.getPrototypeOf(obj) as object | null;
  }
  return [...names];
}
