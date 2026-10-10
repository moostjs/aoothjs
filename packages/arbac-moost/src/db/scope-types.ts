import type { ControlGate, TProjection } from "@aooth/arbac";
import type { NavPropsOf, OwnPropsOf } from "@atscript/typescript/utils";

/**
 * Unwrap a `NavPropsOf<T>[K]` value to its target model type:
 * `Comment[]` → `Comment`, `Task` → `Task`. Used to recurse `with.<K>` into
 * the joined model's own type so per-relation scopes get typed against the
 * RIGHT entity (not the array wrapper).
 */
export type NavTarget<U> = U extends readonly (infer V)[] ? V : U;

/**
 * True only when `T` is `unknown` (or `any`). `unknown extends T` holds for
 * both. Callers use this to pick the legacy untyped shape when no model is
 * annotated.
 */
type IsUnknown<T> = unknown extends T ? true : false;

/**
 * Permissive own-field key set. With a typed `T`, autocompletes against
 * `keyof OwnPropsOf<T>` while still accepting dotted-path projections like
 * `mfa.value` via the `(string & {})` escape hatch. With `T = unknown`,
 * `OwnPropsOf<unknown>` collapses to `unknown` so `keyof` is `never` →
 * falls back to plain `string`.
 */
export type OwnFieldKey<T> = keyof OwnPropsOf<T> extends never
  ? string
  : (keyof OwnPropsOf<T> & string) | (string & {});

/**
 * Same idiom for nav relation names. `NavPropsOf<unknown>` is
 * `Record<string, never>`, so its `keyof` is `string` — the typed branch
 * still resolves to plain `string` (the `(string & {})` escape collapses
 * with `string`).
 */
export type NavRelationKey<T> = keyof NavPropsOf<T> extends never
  ? string
  : (keyof NavPropsOf<T> & string) | (string & {});

/**
 * Typed projection keyed by own-field paths (with dotted-path escape).
 * Falls back to the legacy `TProjection = Record<string, 0 | 1>` for
 * untyped scopes so existing callers that pass the result straight to
 * `unionProjections` / `restrictProjection` keep compiling.
 */
export type ProjectionOf<T> =
  IsUnknown<T> extends true ? TProjection : Partial<Record<OwnFieldKey<T>, 0 | 1>>;

/** The Uniquery controls a gate can only allow or deny (`true` / `false`). */
type BooleanControl =
  | "$select"
  | "$sort"
  | "$nulls"
  | "$skip"
  | "$limit"
  | "$count"
  | "$page"
  | "$size"
  | "$search"
  | "$index"
  | "$fuzzy"
  | "$vector"
  | "$threshold"
  | "$actions"
  | "$rowOrder"
  | "$having"
  | "$center"
  | "$maxDistance"
  | "$minDistance";

/**
 * Typed control gates, matching what `unionControlsPolicy` accepts: only
 * `$with` (nav relation names) and `$groupBy` (own field paths) take a
 * whitelist; every other control is `true` / `false` (a whitelist there
 * throws at scope merge). Unknown control keys are rejected. Falls back to
 * the legacy untyped `Record<string, ControlGate>` for `T = unknown` so
 * internal helpers (`unionControlsPolicy`) and existing untyped call sites
 * keep compiling.
 */
export type ControlsOf<T> =
  IsUnknown<T> extends true
    ? Record<string, ControlGate>
    : {
        $with?: ReadonlyArray<NavRelationKey<T>> | boolean;
        $groupBy?: ReadonlyArray<OwnFieldKey<T>> | boolean;
      } & Partial<Record<BooleanControl, boolean>>;
